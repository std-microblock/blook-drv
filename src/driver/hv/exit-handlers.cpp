// Adapted from jonomango/hv (MIT); see LICENSES/jonomango-hv.txt.
#include "exit-handlers.h"
#include "guest-context.h"
#include "exception-routines.h"
#include "translation.hpp"
#include "hypercalls.h"
#include "vcpu.h"
#include "vmx.h"

#include "hv.h"

namespace hv {

void emulate_cpuid(vcpu* const cpu) {
  auto const ctx = cpu->ctx;

  int regs[4];
  __cpuidex(regs, ctx->eax, ctx->ecx);

  // A processor in non-root operation sets CPUID.1:ECX[31] by itself, which is
  // the single most common way to notice a hypervisor. Report what the real
  // machine reports and clear that bit again.
  if (ctx->eax == 1) regs[2] &= ~static_cast<int>(0x80000000u);

  // Hypervisor-defined leaves are only defined when a hypervisor advertises
  // them through that bit, so they read as zero here.
  if (ctx->eax >= 0x40000000 && ctx->eax <= 0x4FFFFFFF)
    regs[0] = regs[1] = regs[2] = regs[3] = 0;

  ctx->rax = static_cast<uint32_t>(regs[0]);
  ctx->rbx = static_cast<uint32_t>(regs[1]);
  ctx->rcx = static_cast<uint32_t>(regs[2]);
  ctx->rdx = static_cast<uint32_t>(regs[3]);
  skip_instruction();
}

void emulate_rdmsr(vcpu* const cpu) {

  host_exception_info e;

  // the guest could be reading from MSRs that are outside of the MSR bitmap
  // range; Intel SDM specifies that these accesses unconditionally exit.
  auto const msr_value = rdmsr_safe(e, cpu->ctx->ecx);

  if (e.exception_occurred) {
    // reflect the exception back into the guest
    inject_hw_exception(general_protection, 0);
    return;
  }

  cpu->ctx->rax = msr_value & 0xFFFF'FFFF;
  cpu->ctx->rdx = msr_value >> 32;
  skip_instruction();
}

void emulate_wrmsr(vcpu* const cpu) {
  auto const msr = cpu->ctx->ecx;
  auto value = (cpu->ctx->rdx << 32) | cpu->ctx->eax;

  // CET: user mode shadow stacks (IA32_U_CET) are passed through untouched,
  // but supervisor shadow stacks cannot be enforced while this hypervisor runs
  // at CPL0 with the same CET state as the guest - root mode's own returns
  // would raise #CP. Keep only the enable bit clear; the rest of the MSR is
  // written as asked.
  if (msr == IA32_S_CET) value &= ~static_cast<uint64_t>(IA32_S_CET_SH_STK_EN_FLAG);

  // let the guest write to the MSRs
  host_exception_info e;
  wrmsr_safe(e, msr, value);

  if (e.exception_occurred) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // we need to make sure to update EPT memory types if the guest
  // modifies any of the MTRR registers
  if (msr == IA32_MTRR_DEF_TYPE     || msr == IA32_MTRR_FIX64K_00000 ||
      msr == IA32_MTRR_FIX16K_80000 || msr == IA32_MTRR_FIX16K_A0000 ||
     (msr >= IA32_MTRR_FIX4K_C0000  && msr <= IA32_MTRR_FIX4K_F8000) ||
     (msr >= IA32_MTRR_PHYSBASE0    && msr <= IA32_MTRR_PHYSBASE0 + 511)) {
    // update EPT memory types
    if (!read_effective_guest_cr0().cache_disable)
      update_ept_memory_type(cpu->ept);

    vmx_invept(invept_all_context, {});
  }
  skip_instruction();
  return;
}

void emulate_getsec(vcpu*) {
  // inject a #GP(0) since SMX is disabled in the IA32_FEATURE_CONTROL MSR
  inject_hw_exception(general_protection, 0);
}

void emulate_invd(vcpu*) {
  // TODO: properly implement INVD (can probably make a very small stub
  //       that flushes specific cacheline entries prior to executing INVD)
  inject_hw_exception(general_protection, 0);
}

void emulate_xsetbv(vcpu* const cpu) {
  // 3.2.6

  // CR4.OSXSAVE must be 1
  if (!read_effective_guest_cr4().os_xsave) {
    inject_hw_exception(invalid_opcode);
    return;
  }

  xcr0 new_xcr0;
  new_xcr0.flags = (cpu->ctx->rdx << 32) | cpu->ctx->eax;

  // only XCR0 is supported
  if (cpu->ctx->ecx != 0) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if trying to set an unsupported bit
  if (new_xcr0.flags & cpu->cached.xcr0_unsupported_mask) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if clearing XCR0.X87
  if (!new_xcr0.x87) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if XCR0.AVX is 1 while XCRO.SSE is cleared
  if (new_xcr0.avx && !new_xcr0.sse) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if XCR0.AVX is clear and XCR0.opmask, XCR0.ZMM_Hi256, or XCR0.Hi16_ZMM is set
  if (!new_xcr0.avx && (new_xcr0.opmask || new_xcr0.zmm_hi256 || new_xcr0.zmm_hi16)) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if setting XCR0.BNDREG or XCR0.BNDCSR while not setting the other
  if (new_xcr0.bndreg != new_xcr0.bndcsr) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if setting XCR0.opmask, XCR0.ZMM_Hi256, or XCR0.Hi16_ZMM while not setting all of them
  if (new_xcr0.opmask != new_xcr0.zmm_hi256 || new_xcr0.zmm_hi256 != new_xcr0.zmm_hi16) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  host_exception_info e;
  xsetbv_safe(e, cpu->ctx->ecx, new_xcr0.flags);

  if (e.exception_occurred) {
    // TODO: assert that it was a #GP(0) that occurred, although I really
    //       doubt that any other exception could happen (according to manual).
    inject_hw_exception(general_protection, 0);
    return;
  }

  skip_instruction();
}

void emulate_vmxon(vcpu*) { inject_hw_exception(invalid_opcode); }

extern "C" char blook_vmcall_site;
void emulate_vmcall(vcpu* const cpu) {
  if (current_guest_cpl() != 0 || vmx_vmread(VMCS_GUEST_RIP) != reinterpret_cast<uint64_t>(&blook_vmcall_site) ||
      (cpu->ctx->rax >> 8) != call_tag) { inject_hw_exception(invalid_opcode); return; }
  auto op = static_cast<operation>(cpu->ctx->rax & 0xff);
  cpu->ctx->rax = 0;
  switch (op) {
    case operation::ping: cpu->ctx->rax = hypervisor_signature; break;
    case operation::stop: cpu->stop_virtualization = true; cpu->ctx->rax = 1; break;
    case operation::install: {
      auto spec = reinterpret_cast<const blook::hook_spec*>(cpu->ctx->rcx);
      if (reinterpret_cast<uint64_t>(spec) < 0xffff800000000000ull) break;
      cpu->ctx->rax = install_ept_hook(cpu->ept, *spec);
      break;
    }
    case operation::refresh: refresh_ept_hook(cpu->ept, cpu->ctx->rcx); cpu->ctx->rax = 1; break;
    case operation::remove: remove_ept_hook(cpu->ept, cpu->ctx->rcx); cpu->ctx->rax = 1; break;
    case operation::window_begin: cpu->ctx->rax = begin_ept_window(cpu->ept, cpu->ctx->rcx); break;
    case operation::window_end: cpu->ctx->rax = end_ept_window(cpu->ept, cpu->ctx->rcx); break;
    default: inject_hw_exception(invalid_opcode); return;
  }
  skip_instruction();
}

void handle_vmx_preemption(vcpu*) {
  // do nothing.
}

namespace {
// Reads up to 15 bytes of the guest instruction at `rip` through the guest's
// own page tables. At most two page translations are needed.
bool read_guest_instruction(uint64_t const rip, uint8_t (&bytes)[15]) {
    auto const cr3 = vmx_vmread(VMCS_GUEST_CR3);
    size_t done = 0;
    uint64_t address = rip;
    while (done < sizeof(bytes)) {
        auto const physical = translate_guest(cr3, address);
        if (!physical) return false;
        auto const chunk = static_cast<size_t>(4096 - (physical & 0xfff));
        auto const want = (sizeof(bytes) - done) < chunk ? (sizeof(bytes) - done) : chunk;
        host_exception_info exception{};
        memcpy_safe(exception, bytes + done, host_physical_memory_base + physical, want);
        if (exception.exception_occurred) return false;
        done += want;
        address += want;
    }
    return true;
}

bool is_legacy_prefix(uint8_t const byte) {
    switch (byte) {
        case 0x26: case 0x2e: case 0x36: case 0x3e: case 0x64: case 0x65:
        case 0x66: case 0x67: case 0xf0: case 0xf2: case 0xf3:
            return true;
        default:
            return false;
    }
}

// Length of an operand described by the modrm byte at `index`: the modrm byte
// itself plus SIB and displacement when the operand is in memory.
uint32_t decode_modrm_length(uint8_t const* bytes, size_t const index) {
    auto const modrm = bytes[index];
    size_t i = index + 1;
    auto const mod = static_cast<uint32_t>(modrm >> 6);
    auto const rm = static_cast<uint32_t>(modrm & 7);
    if (mod == 3) return static_cast<uint32_t>(i);
    if (rm == 4) {
        if (i >= 15) return 0;
        auto const sib = bytes[i++];
        if (mod == 0 && (sib & 7) == 5) i += 4;
        else if (mod == 1) i += 1;
        else if (mod == 2) i += 4;
    } else if (mod == 0 && rm == 5) {
        i += 4;
    } else if (mod == 1) {
        i += 1;
    } else if (mod == 2) {
        i += 4;
    }
    return i <= 15 ? static_cast<uint32_t>(i) : 0;
}
}  // namespace

// Length of the instruction that caused the current vm-exit, decoded from the
// guest's own bytes.
//
// VMCS_VMEXIT_INSTRUCTION_LENGTH must not be trusted: measured on this machine,
// 3.7M control-register exits reported length 3 and length 35 (35 is not a
// possible encoding), and the field is not documented as valid for every exit
// class either. Skipping by a wrong value resumes the guest in the middle of an
// instruction, which is what produced the unexplained kernel faults and
// bugchecks during bring-up.
uint32_t decode_guest_instruction_length() {
    uint8_t bytes[15]{};
    auto const rip = vmx_vmread(VMCS_GUEST_RIP);
    auto const reported = static_cast<uint32_t>(vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH));
    auto const exit_reason = static_cast<uint32_t>(vmx_vmread(VMCS_EXIT_REASON)) & 0xffffu;
    auto const qualification = vmx_vmread(VMCS_EXIT_QUALIFICATION);
    auto const access_type = exit_reason == VMX_EXIT_REASON_MOV_CR
                             ? static_cast<uint32_t>((qualification >> 12) & 0xfu)
                             : 0u;
    if (!read_guest_instruction(rip, bytes)) {
        ++cr_stats.decoded_failed;
        record_length_mismatch(rip, qualification, 0, reported, exit_reason, access_type,
                               bytes, sizeof(bytes));
        return 0;
    }
    size_t i = 0;
    while (i < sizeof(bytes) && is_legacy_prefix(bytes[i])) ++i;
    if (i < sizeof(bytes) && (bytes[i] & 0xf0) == 0x40) ++i;  // REX

    uint32_t length = 0;
    if (i + 1 < sizeof(bytes) && bytes[i] == 0x0f) {
        auto const opcode = bytes[i + 1];
        auto const after = i + 2;
        switch (opcode) {
            case 0x08:  // INVD
            case 0x30:  // WRMSR
            case 0x31:  // RDTSC
            case 0x32:  // RDMSR
            case 0x37:  // GETSEC
            case 0xa2:  // CPUID
                length = static_cast<uint32_t>(after);
                break;
            case 0x01:  // VMCALL/VMLAUNCH/VMRESUME/VMXOFF/VMFUNC/RDTSCP/XSETBV/LMSW
                if (after < sizeof(bytes)) {
                    auto const modrm = bytes[after];
                    if (modrm == 0xc1 || modrm == 0xc2 || modrm == 0xc3 ||
                        modrm == 0xc4 || modrm == 0xd4 || modrm == 0xd1 ||
                        modrm == 0xf9 || ((modrm >> 3) & 7) == 6)
                        length = static_cast<uint32_t>(after + 1);
                }
                break;
            case 0x20:  // MOV from CR
            case 0x22:  // MOV to CR
                if (after < sizeof(bytes)) length = decode_modrm_length(bytes, after);
                break;
            case 0xc7:  // VMCLEAR/VMPTRLD/VMPTRST/INVEPT/INVVPID
                if (after < sizeof(bytes)) length = decode_modrm_length(bytes, after);
                break;
            default:
                break;
        }
    }
    if (!length) {
        ++cr_stats.decoded_failed;
        record_length_mismatch(rip, qualification, 0, reported, exit_reason, access_type,
                               bytes, sizeof(bytes));
        return 0;
    }
    ++cr_stats.decoded;
    if (reported != length) {
        ++cr_stats.decoded_mismatch;
        record_length_mismatch(rip, qualification, length, reported, exit_reason, access_type,
                               bytes, sizeof(bytes));
    }
    return length;
}

void emulate_mov_to_cr0(vcpu* const cpu, uint64_t const gpr) {
  // 2.4.3
  // 3.2.5
  // 3.4.10.1
  // 3.26.3.2.1

  cr0 new_cr0;
  new_cr0.flags = read_guest_gpr(cpu->ctx, gpr);

  auto const curr_cr0 = read_effective_guest_cr0();
  auto const curr_cr4 = read_effective_guest_cr4();

  // CR0[15:6] is always 0
  new_cr0.reserved1 = 0;

  // CR0[17] is always 0
  new_cr0.reserved2 = 0;

  // CR0[28:19] is always 0
  new_cr0.reserved3 = 0;

  // CR0.ET is always 1
  new_cr0.extension_type = 1;

  // #GP(0) if setting any reserved bits in CR0[63:32]
  if (new_cr0.reserved4) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if setting CR0.PG while CR0.PE is clear
  if (new_cr0.paging_enable && !new_cr0.protection_enable) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if invalid bit combination
  if (!new_cr0.cache_disable && new_cr0.not_write_through) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if an attempt is made to clear CR0.PG
  if (!new_cr0.paging_enable) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if an attempt is made to clear CR0.WP while CR4.CET is set
  if (!new_cr0.write_protect && curr_cr4.control_flow_enforcement_enable) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // the guest tried to modify CR0.CD or CR0.NW, which must be updated manually
  if (new_cr0.cache_disable     != curr_cr0.cache_disable ||
      new_cr0.not_write_through != curr_cr0.not_write_through) {
    // TODO: should we care about NW?
    if (new_cr0.cache_disable)
      set_ept_memory_type(cpu->ept, MEMORY_TYPE_UNCACHEABLE);
    else
      update_ept_memory_type(cpu->ept);

    vmx_invept(invept_all_context, {});
  }


  vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, new_cr0.flags);

  // make sure to account for VMX reserved bits when setting the real CR0
  new_cr0.flags |= cpu->cached.vmx_cr0_fixed0;
  new_cr0.flags &= cpu->cached.vmx_cr0_fixed1;

  vmx_vmwrite(VMCS_GUEST_CR0, new_cr0.flags);
  skip_instruction();
}

void emulate_mov_to_cr3(vcpu* const cpu, uint64_t const gpr) {
  cr3 new_cr3;
  new_cr3.flags = read_guest_gpr(cpu->ctx, gpr);

  auto const curr_cr4 = read_effective_guest_cr4();

  bool invalidate_tlb = true;

  // 3.4.10.4.1
  if (curr_cr4.pcid_enable && (new_cr3.flags & (1ull << 63))) {
    invalidate_tlb = false;
    new_cr3.flags &= ~(1ull << 63);
  }

  // a mask where bits [63:MAXPHYSADDR] are set to 1
  auto const reserved_mask = ~((1ull << cpu->cached.max_phys_addr) - 1);

  // 3.2.5
  if (new_cr3.flags & reserved_mask) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // 3.28.4.3.3
  //
  // A guest CR3 write without the no-flush bit is supposed to drop the
  // translations of the context being left *and* those of the context being
  // entered: writing a PCID's CR3 is exactly how the guest flushes that
  // context before recycling the PCID. Invalidating only the current (old)
  // context - which is what the instruction would do at the moment of the
  // intercept, because the CPU still holds the old CR3 - leaves the recycled
  // PCID's stale entries behind. A stale entry can be a negative one ("not
  // present"), and the next owner of that PCID then faults on a perfectly
  // valid access. INVVPID invalidates for the current PCID only, so the
  // conservative correct answer for a CR3 write is the all-context form.
  if (invalidate_tlb) {
    vmx_invvpid(invvpid_all_context, {});
  }

  // it is now safe to write the new guest cr3
  vmx_vmwrite(VMCS_GUEST_CR3, new_cr3.flags);
  reset_ept_context(cpu->ept);
  skip_instruction();
}

void emulate_mov_to_cr4(vcpu* const cpu, uint64_t const gpr) {
  // 2.4.3
  // 2.6.2.1
  // 3.2.5
  // 3.4.10.1
  // 3.4.10.4.1

  cr4 new_cr4;
  new_cr4.flags = read_guest_gpr(cpu->ctx, gpr);

  cr3 curr_cr3;
  curr_cr3.flags = vmx_vmread(VMCS_GUEST_CR3);

  auto const curr_cr0 = read_effective_guest_cr0();
  auto const curr_cr4 = read_effective_guest_cr4();

  // #GP(0) if an attempt is made to set CR4.SMXE when SMX is not supported
  if (!cpu->cached.cpuid_01.cpuid_feature_information_ecx.safer_mode_extensions
      && new_cr4.smx_enable) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if an attempt is made to write a 1 to any reserved bits
  if (new_cr4.reserved1 || new_cr4.reserved2) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if an attempt is made to change CR4.PCIDE from 0 to 1 while CR3[11:0] != 000H
  if ((new_cr4.pcid_enable && !curr_cr4.pcid_enable) && (curr_cr3.flags & 0xFFF)) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if CR4.PAE is cleared
  if (!new_cr4.physical_address_extension) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if CR4.LA57 is enabled
  if (new_cr4.linear_addresses_57_bit) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // #GP(0) if CR4.CET == 1 and CR0.WP == 0
  if (new_cr4.control_flow_enforcement_enable && !curr_cr0.write_protect) {
    inject_hw_exception(general_protection, 0);
    return;
  }

  // invalidate TLB entries if required
  if (new_cr4.page_global_enable != curr_cr4.page_global_enable ||
      !new_cr4.pcid_enable && curr_cr4.pcid_enable ||
      new_cr4.smep_enable && !curr_cr4.smep_enable) {
    invvpid_descriptor desc;
    desc.linear_address = 0;
    desc.reserved1      = 0;
    desc.reserved2      = 0;
    desc.vpid           = guest_vpid;
    vmx_invvpid(invvpid_single_context, desc);
  }
  

  vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, new_cr4.flags);

  // make sure to account for VMX reserved bits when setting the real CR4
  new_cr4.flags |= cpu->cached.vmx_cr4_fixed0;
  new_cr4.flags &= cpu->cached.vmx_cr4_fixed1;

  vmx_vmwrite(VMCS_GUEST_CR4, new_cr4.flags);
  skip_instruction();
}

void emulate_mov_from_cr3(vcpu* const cpu, uint64_t const gpr) {
  write_guest_gpr(cpu->ctx, gpr, vmx_vmread(VMCS_GUEST_CR3));
  skip_instruction();
}

void emulate_clts(vcpu* const cpu) {
  // clear CR0.TS in the read shadow
  vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW,
    vmx_vmread(VMCS_CTRL_CR0_READ_SHADOW) & ~CR0_TASK_SWITCHED_FLAG);

  // clear CR0.TS in the real CR0 register
  vmx_vmwrite(VMCS_GUEST_CR0,
    vmx_vmread(VMCS_GUEST_CR0) & ~CR0_TASK_SWITCHED_FLAG);
  skip_instruction();
}

void emulate_lmsw(vcpu* const cpu, uint16_t const value) {
  // 3.25.1.3

  cr0 new_cr0;
  new_cr0.flags = value;

  // update the guest CR0 read shadow
  cr0 shadow_cr0;
  shadow_cr0.flags = vmx_vmread(VMCS_CTRL_CR0_READ_SHADOW);
  shadow_cr0.protection_enable   = new_cr0.protection_enable;
  shadow_cr0.monitor_coprocessor = new_cr0.monitor_coprocessor;
  shadow_cr0.emulate_fpu         = new_cr0.emulate_fpu;
  shadow_cr0.task_switched       = new_cr0.task_switched;
  vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, shadow_cr0.flags);

  // update the real guest CR0.
  // we don't have to worry about VMX reserved bits since CR0.PE (the only
  // reserved bit) can't be cleared to 0 by the LMSW instruction while in
  // protected mode.
  cr0 real_cr0;
  real_cr0.flags = vmx_vmread(VMCS_GUEST_CR0);
  real_cr0.protection_enable   = new_cr0.protection_enable;
  real_cr0.monitor_coprocessor = new_cr0.monitor_coprocessor;
  real_cr0.emulate_fpu         = new_cr0.emulate_fpu;
  real_cr0.task_switched       = new_cr0.task_switched;
  vmx_vmwrite(VMCS_GUEST_CR0, real_cr0.flags);
  skip_instruction();
}

void handle_mov_cr(vcpu* const cpu) {
  vmx_exit_qualification_mov_cr qualification;
  qualification.flags = vmx_vmread(VMCS_EXIT_QUALIFICATION);

  // Bring-up diagnostic: what did the processor claim the instruction length
  // was? See cr_exit_stats in hv.h.
  {
    auto const slot = static_cast<uint32_t>(qualification.access_type);
    auto const length = static_cast<uint32_t>(vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH));
    if (slot < 4) {
      ++cr_stats.count[slot];
      if (length < 64) cr_stats.length_mask[slot] |= 1ull << length;
      if (length > cr_stats.max_length[slot]) cr_stats.max_length[slot] = length;
    }
  }

  switch (qualification.access_type) {
  // MOV CRn, XXX
  case VMX_EXIT_QUALIFICATION_ACCESS_MOV_TO_CR:
    switch (qualification.control_register) {
    case VMX_EXIT_QUALIFICATION_REGISTER_CR0:
      emulate_mov_to_cr0(cpu, qualification.general_purpose_register);
      break;
    case VMX_EXIT_QUALIFICATION_REGISTER_CR3:
      emulate_mov_to_cr3(cpu, qualification.general_purpose_register);
      break;
    case VMX_EXIT_QUALIFICATION_REGISTER_CR4:
      emulate_mov_to_cr4(cpu, qualification.general_purpose_register);
      break;
    }
    break;
  // MOV XXX, CRn
  case VMX_EXIT_QUALIFICATION_ACCESS_MOV_FROM_CR:
    // TODO: assert that we're accessing CR3 (and not CR8)
    emulate_mov_from_cr3(cpu, qualification.general_purpose_register);
    break;
  // CLTS
  case VMX_EXIT_QUALIFICATION_ACCESS_CLTS:
    emulate_clts(cpu);
    break;
  // LMSW XXX
  case VMX_EXIT_QUALIFICATION_ACCESS_LMSW:
    emulate_lmsw(cpu, qualification.lmsw_source_data);
    break;
  }
}

void handle_nmi_window(vcpu* const cpu) {
  if (cpu->queued_nmis) --cpu->queued_nmis;

  // inject the NMI into the guest
  inject_nmi();

  if (cpu->queued_nmis == 0) {
    // disable NMI-window exiting since we have no more NMIs to inject
    auto ctrl = read_ctrl_proc_based();
    ctrl.nmi_window_exiting = 0;
    write_ctrl_proc_based(ctrl);
  }
  
  // there is the possibility that a host NMI occurred right before we
  // disabled NMI-window exiting. make sure to re-enable it if this is the case.
  if (cpu->queued_nmis > 0) {
    auto ctrl = read_ctrl_proc_based();
    ctrl.nmi_window_exiting = 1;
    write_ctrl_proc_based(ctrl);
  }
}

namespace {
// The exceptions that combine into a double fault when one happens while the
// processor is delivering one of them (SDM: "a contributory exception or a
// page fault during the delivery of a contributory exception or a page
// fault").
bool contributory(uint32_t const vector) {
  switch (vector) {
    case 0:   // #DE
    case 10:  // #TS
    case 11:  // #NP
    case 12:  // #SS
    case 13:  // #GP
    case 14:  // #PF
      return true;
    default:
      return false;
  }
}
}  // namespace

void handle_exception_or_nmi(vcpu* const cpu) {
  vmexit_interrupt_information info{};
  info.flags = static_cast<uint32_t>(vmx_vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION));
  if (!info.valid) fatal_root_error();

  if (info.interruption_type == non_maskable_interrupt) {
    // enqueue an NMI to be injected into the guest later on
    ++cpu->queued_nmis;

    auto ctrl = read_ctrl_proc_based();
    ctrl.nmi_window_exiting = 1;
    write_ctrl_proc_based(ctrl);
    return;
  }

  // Only reachable while the bring-up fault trace is on (see hv.h): the guest
  // would normally see these exceptions without any exit at all.
  if (!fault_trace_enabled()) fatal_root_error();

  auto const error = info.error_code_valid
                       ? static_cast<uint32_t>(vmx_vmread(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE))
                       : 0;

  // The ring is circular: it keeps the most recent faults, which are the
  // interesting ones when the machine dies shortly after they happened.
  auto const vectoring = static_cast<uint32_t>(vmx_vmread(VMCS_IDT_VECTORING_INFORMATION));
  bool const delivering = (vectoring & 0x80000000u) != 0;
  bool const double_fault = delivering && contributory(info.vector) &&
                            contributory(vectoring & 0xffu);
  if (fault_trace_records()) {
    auto const sequence = ++fault_trace_total;
    auto& record = fault_trace[static_cast<uint32_t>((sequence - 1) % fault_trace_count)];
    record.sequence = sequence;
    record.rip = vmx_vmread(VMCS_GUEST_RIP);
    record.cr2 = __readcr2();
    record.cr3 = vmx_vmread(VMCS_GUEST_CR3);
    record.error = error;
    record.vcpu = reinterpret_cast<uint64_t>(cpu);
    record.vector = info.vector;
    record.type = info.interruption_type;
    record.idt_vectoring = vectoring;
    record.double_fault = double_fault ? 1u : 0u;
  } else {
    ++fault_trace_total;
  }

  // The guest may have been delivering an event when this exception happened.
  // The processor would then combine the two: a page fault or a contributory
  // exception raised while delivering one of those becomes a double fault. An
  // intercepted exception never gets that far - VM entry clears the
  // IDT-vectoring information - so the combination has to happen here. Without
  // it the guest sees a plain page fault, retries the same instruction and
  // faults again, forever.
  if (double_fault) {
    // #DF pushes a zero error code.
    inject_hw_exception(8, 0);
    return;
  }

  // The bitmap only covers faults, so the guest RIP already points at the
  // instruction the processor reports and nothing has to be skipped. Deliver
  // the same exception the guest would have taken by itself.
  if (info.error_code_valid)
    inject_hw_exception(info.vector, error);
  else
    inject_hw_exception(info.vector);
}

void handle_vmx_instruction(vcpu*) {
  // inject #UD for every VMX instruction since we
  // don't allow the guest to ever enter VMX operation.
  inject_hw_exception(invalid_opcode);
}

void handle_ept_violation(vcpu* const cpu) {
  vmx_exit_qualification_ept_violation q{};
  q.flags = vmx_vmread(VMCS_EXIT_QUALIFICATION);
  handle_page_access(cpu->ept, vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS),
                    q.execute_access != 0, vmx_vmread(VMCS_GUEST_RIP));
}

void emulate_rdtsc(vcpu* const cpu) {
  auto const tsc = __rdtsc();

  // return current TSC
  cpu->ctx->rax = tsc & 0xFFFFFFFF;
  cpu->ctx->rdx = (tsc >> 32) & 0xFFFFFFFF;

  skip_instruction();
}

void emulate_rdtscp(vcpu* const cpu) {
  unsigned int aux = 0;
  auto const tsc = __rdtscp(&aux);

  // return current TSC
  cpu->ctx->rax = tsc & 0xFFFFFFFF;
  cpu->ctx->rdx = (tsc >> 32) & 0xFFFFFFFF;
  cpu->ctx->rcx = aux;

  skip_instruction();
}

void handle_monitor_trap_flag(vcpu* const cpu) { rearm_ept(cpu->ept); }

void handle_ept_misconfiguration(vcpu*) { fatal_root_error(); }

} // namespace hv

