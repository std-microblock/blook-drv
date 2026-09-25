// Adapted from jonomango/hv (MIT); see LICENSES/jonomango-hv.txt.
#include "vcpu.h"
#include <ntimage.h>
#include "hv.h"
#include "gdt.h"
#include "idt.h"
#include "vmx.h"
#include "vmcs.h"
#include "trap-frame.h"
#include "exit-handlers.h"
#include "exception-routines.h"
#include "translation.hpp"

// first byte at the start of the image
extern "C" uint8_t __ImageBase;

namespace hv {

// defined in vm-launch.asm
bool vm_launch();

// cache certain fixed values (CPUID results, MSRs, etc) that are used
// frequently during VMX operation (to speed up vm-exit handling).
static void cache_cpu_data(vcpu_cached_data& cached) {
  __cpuid(reinterpret_cast<int*>(&cached.cpuid_01), 0x01);

  // VMX needs to be enabled to read from certain VMX_* MSRS
  if (!cached.cpuid_01.cpuid_feature_information_ecx.virtual_machine_extensions)
    return;

  cpuid_eax_80000008 cpuid_80000008;
  __cpuid(reinterpret_cast<int*>(&cpuid_80000008), 0x80000008);

  cached.max_phys_addr = cpuid_80000008.eax.number_of_physical_address_bits;

  cached.vmx_cr0_fixed0 = __readmsr(IA32_VMX_CR0_FIXED0);
  cached.vmx_cr0_fixed1 = __readmsr(IA32_VMX_CR0_FIXED1);
  cached.vmx_cr4_fixed0 = __readmsr(IA32_VMX_CR4_FIXED0);
  cached.vmx_cr4_fixed1 = __readmsr(IA32_VMX_CR4_FIXED1);

  cpuid_eax_0d_ecx_00 cpuid_0d;
  __cpuidex(reinterpret_cast<int*>(&cpuid_0d), 0x0D, 0x00);
  
  // features in XCR0 that are supported
  cached.xcr0_unsupported_mask = ~((static_cast<uint64_t>(
    cpuid_0d.edx.flags) << 32) | cpuid_0d.eax.flags);

  cached.feature_control.flags = __readmsr(IA32_FEATURE_CONTROL);
  cached.vmx_misc.flags         = __readmsr(IA32_VMX_MISC);


}

// enable VMX operation prior to execution of the VMXON instruction
static bool enable_vmx_operation(vcpu const* const cpu) {
  // 3.23.6
  if (!cpu->cached.cpuid_01.cpuid_feature_information_ecx.virtual_machine_extensions) {
    DbgPrint("[hv] VMX not supported by CPUID.\n");
    return false;
  }

  // 3.23.7
  if (!cpu->cached.feature_control.lock_bit ||
      !cpu->cached.feature_control.enable_vmx_outside_smx) {
    DbgPrint("[hv] VMX not enabled outside SMX.\n");
    return false;
  }

  _disable();

  auto cr0 = __readcr0();
  auto cr4 = __readcr4();

  // 3.23.7
  cr4 |= CR4_VMX_ENABLE_FLAG;

  // 3.23.8
  cr0 |= cpu->cached.vmx_cr0_fixed0;
  cr0 &= cpu->cached.vmx_cr0_fixed1;
  cr4 |= cpu->cached.vmx_cr4_fixed0;
  cr4 &= cpu->cached.vmx_cr4_fixed1;

  __writecr0(cr0);
  __writecr4(cr4);


  return true;
}

// enter VMX operation by executing VMXON
static bool enter_vmx_operation(vmxon& vmxon_region) {
  ia32_vmx_basic_register vmx_basic;
  vmx_basic.flags = __readmsr(IA32_VMX_BASIC);

  // 3.24.11.5
  vmxon_region.revision_id = vmx_basic.vmcs_revision_id;
  vmxon_region.must_be_zero = 0;

  auto vmxon_phys = MmGetPhysicalAddress(&vmxon_region).QuadPart;
  NT_ASSERT(vmxon_phys % 0x1000 == 0);

  // enter vmx operation
  if (!vmx_vmxon(vmxon_phys)) {
    DbgPrint("[hv] VMXON failed.\n");
    return false;
  }

  // 3.28.3.3.4
  vmx_invept(invept_all_context, {});

  return true;
}

// load the VMCS pointer by executing VMPTRLD
static bool load_vmcs_pointer(vmcs& vmcs_region) {
  ia32_vmx_basic_register vmx_basic;
  vmx_basic.flags = __readmsr(IA32_VMX_BASIC);

  // 3.24.2
  vmcs_region.revision_id = vmx_basic.vmcs_revision_id;
  vmcs_region.shadow_vmcs_indicator = 0;

  auto vmcs_phys = MmGetPhysicalAddress(&vmcs_region).QuadPart;
  NT_ASSERT(vmcs_phys % 0x1000 == 0);

  if (!vmx_vmclear(vmcs_phys)) {
    DbgPrint("[hv] VMCLEAR failed.\n");
    return false;
  }

  if (!vmx_vmptrld(vmcs_phys)) {
    DbgPrint("[hv] VMPTRLD failed.\n");
    return false;
  }

  return true;
}

// enable vm-exits for MTRR MSR writes
static void enable_mtrr_exiting(vcpu* const cpu) {
  ia32_mtrr_capabilities_register mtrr_cap;
  mtrr_cap.flags = __readmsr(IA32_MTRR_CAPABILITIES);

  enable_exit_for_msr_write(cpu->msr_bitmap, IA32_MTRR_DEF_TYPE, true);

  // enable exiting for fixed-range MTRRs
  if (mtrr_cap.fixed_range_supported) {
    enable_exit_for_msr_write(cpu->msr_bitmap, IA32_MTRR_FIX64K_00000, true);
    enable_exit_for_msr_write(cpu->msr_bitmap, IA32_MTRR_FIX16K_80000, true);
    enable_exit_for_msr_write(cpu->msr_bitmap, IA32_MTRR_FIX16K_A0000, true);

    for (uint32_t i = 0; i < 8; ++i)
      enable_exit_for_msr_write(cpu->msr_bitmap, IA32_MTRR_FIX4K_C0000 + i, true);
  }

  // enable exiting for variable-range MTRRs
  for (uint32_t i = 0; i < mtrr_cap.variable_range_count; ++i) {
    enable_exit_for_msr_write(cpu->msr_bitmap, IA32_MTRR_PHYSBASE0 + i * 2, true);
    enable_exit_for_msr_write(cpu->msr_bitmap, IA32_MTRR_PHYSMASK0 + i * 2, true);
  }
}

// initialize external structures that are not included in the VMCS
static void prepare_external_structures(vcpu* const cpu) {
  memset(&cpu->msr_bitmap, 0, sizeof(cpu->msr_bitmap));


  enable_mtrr_exiting(cpu);

  // CET: IA32_S_CET writes are intercepted so the supervisor shadow stack
  // cannot be switched on behind root mode's back (see emulate_wrmsr). The
  // rest of the CET state needs no interception: it is shared with root mode
  // and never switched by the VMCS.
  enable_exit_for_msr_write(cpu->msr_bitmap, IA32_S_CET, true);

  // we don't care about anything that's in the TSS
  memset(&cpu->host_tss, 0, sizeof(cpu->host_tss));

  prepare_host_idt(cpu->host_idt);
  prepare_host_gdt(cpu->host_gdt, &cpu->host_tss);


}

// call the appropriate exit-handler for this vm-exit
static void dispatch_vm_exit(vcpu* const cpu, vmx_vmexit_reason const reason) {
  switch (reason.basic_exit_reason) {
  case VMX_EXIT_REASON_EXCEPTION_OR_NMI:             handle_exception_or_nmi(cpu);     break;
  case VMX_EXIT_REASON_EXECUTE_GETSEC:               emulate_getsec(cpu);              break;
  case VMX_EXIT_REASON_EXECUTE_INVD:                 emulate_invd(cpu);                break;
  case VMX_EXIT_REASON_NMI_WINDOW:                   handle_nmi_window(cpu);           break;
  case VMX_EXIT_REASON_EXECUTE_CPUID:                emulate_cpuid(cpu);               break;
  case VMX_EXIT_REASON_MOV_CR:                       handle_mov_cr(cpu);               break;
  case VMX_EXIT_REASON_EXECUTE_RDMSR:                emulate_rdmsr(cpu);               break;
  case VMX_EXIT_REASON_EXECUTE_WRMSR:                emulate_wrmsr(cpu);               break;
  case VMX_EXIT_REASON_EXECUTE_XSETBV:               emulate_xsetbv(cpu);              break;
  case VMX_EXIT_REASON_EXECUTE_VMXON:                emulate_vmxon(cpu);               break;
  case VMX_EXIT_REASON_EXECUTE_VMCALL:               emulate_vmcall(cpu);              break;
  case VMX_EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED: handle_vmx_preemption(cpu);       break;
  case VMX_EXIT_REASON_EPT_VIOLATION:                handle_ept_violation(cpu);        break;
  case VMX_EXIT_REASON_EXECUTE_RDTSC:                emulate_rdtsc(cpu);               break;
  case VMX_EXIT_REASON_EXECUTE_RDTSCP:               emulate_rdtscp(cpu);              break;
  case VMX_EXIT_REASON_MONITOR_TRAP_FLAG:            handle_monitor_trap_flag(cpu);    break;
  case VMX_EXIT_REASON_EPT_MISCONFIGURATION:         handle_ept_misconfiguration(cpu); break;
  // VMX instructions (except for VMXON and VMCALL)
  case VMX_EXIT_REASON_EXECUTE_INVEPT:
  case VMX_EXIT_REASON_EXECUTE_INVVPID:
  case VMX_EXIT_REASON_EXECUTE_VMCLEAR:
  case VMX_EXIT_REASON_EXECUTE_VMLAUNCH:
  case VMX_EXIT_REASON_EXECUTE_VMPTRLD:
  case VMX_EXIT_REASON_EXECUTE_VMPTRST:
  case VMX_EXIT_REASON_EXECUTE_VMREAD:
  case VMX_EXIT_REASON_EXECUTE_VMRESUME:
  case VMX_EXIT_REASON_EXECUTE_VMWRITE:
  case VMX_EXIT_REASON_EXECUTE_VMXOFF:
  case VMX_EXIT_REASON_EXECUTE_VMFUNC:               handle_vmx_instruction(cpu);    break;

  // unhandled VM-exit
  default:
    fatal_root_error();
    break;
  }
}

// called for every vm-exit
bool handle_vm_exit(guest_context* const ctx) {
  // get the current vcpu
  auto const cpu = reinterpret_cast<vcpu*>(_readfsbase_u64());
  cpu->ctx = ctx;

  vmx_vmexit_reason reason;
  reason.flags = static_cast<uint32_t>(vmx_vmread(VMCS_EXIT_REASON));

  cpu->stop_virtualization   = false;

  // Only exits that exist because an instruction was intercepted have a cost
  // that can be removed from the guest clock without accumulating error.
  switch (reason.basic_exit_reason) {
  case VMX_EXIT_REASON_EXECUTE_CPUID:
  case VMX_EXIT_REASON_EXECUTE_RDMSR:
  case VMX_EXIT_REASON_EXECUTE_WRMSR:
  case VMX_EXIT_REASON_EXECUTE_XSETBV:
  case VMX_EXIT_REASON_EXECUTE_VMCALL:
  case VMX_EXIT_REASON_MOV_CR:
    cpu->hide_vm_exit_overhead = true;
    break;
  default:
    cpu->hide_vm_exit_overhead = false;
    break;
  }

  if (reason.vm_entry_failure) fatal_root_error();
  if (reason.basic_exit_reason != VMX_EXIT_REASON_EPT_VIOLATION && cpu->ept.temporary_count)
    rearm_ept(cpu->ept);
  dispatch_vm_exit(cpu, reason);

  // restore guest state. the assembly code is responsible for restoring
  // RIP, CS, RFLAGS, RSP, SS, CR0, CR4, as well as the usual fields in
  // the guest_context structure. the C++ code is responsible for the rest.
  if (cpu->stop_virtualization) {
    // TODO: assert that CPL is 0

    // ensure that the control register shadows reflect the guest values
    vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, read_effective_guest_cr0().flags);
    vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, read_effective_guest_cr4().flags);

    // DR7
    __writedr(7, vmx_vmread(VMCS_GUEST_DR7));

    // MSRs
    __writemsr(IA32_SYSENTER_CS,      vmx_vmread(VMCS_GUEST_SYSENTER_CS));
    __writemsr(IA32_SYSENTER_ESP,     vmx_vmread(VMCS_GUEST_SYSENTER_ESP));
    __writemsr(IA32_SYSENTER_EIP,     vmx_vmread(VMCS_GUEST_SYSENTER_EIP));
    __writemsr(IA32_PAT,              vmx_vmread(VMCS_GUEST_PAT));
    __writemsr(IA32_DEBUGCTL,         vmx_vmread(VMCS_GUEST_DEBUGCTL));

    // CR3
    __writecr3(vmx_vmread(VMCS_GUEST_CR3));

    // GDT
    segment_descriptor_register_64 gdtr;
    gdtr.base_address = vmx_vmread(VMCS_GUEST_GDTR_BASE);
    gdtr.limit = static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_GDTR_LIMIT));
    _lgdt(&gdtr);

    // IDT
    segment_descriptor_register_64 idtr;
    idtr.base_address = vmx_vmread(VMCS_GUEST_IDTR_BASE);
    idtr.limit = static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_IDTR_LIMIT));
    __lidt(&idtr);

    segment_selector guest_tr;
    guest_tr.flags = static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_TR_SELECTOR));

    // TSS
    (reinterpret_cast<segment_descriptor_32*>(gdtr.base_address)
      + guest_tr.index)->type = SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE;
    write_tr(guest_tr.flags);

    // segment selectors
    write_ds(static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_DS_SELECTOR)));
    write_es(static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_ES_SELECTOR)));
    write_fs(static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_FS_SELECTOR)));
    write_gs(static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_GS_SELECTOR)));
    write_ldtr(static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_LDTR_SELECTOR)));

    // FS and GS base address
    _writefsbase_u64(vmx_vmread(VMCS_GUEST_FS_BASE));
    _writegsbase_u64(vmx_vmread(VMCS_GUEST_GS_BASE));

    return true;
  }

  // Hide the world switch from the clocks a guest can read before resuming it.
  hide_vm_exit_overhead(cpu);

  vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, cpu->tsc_offset);
  if (cpu->cached.preemption_timer_supported)
    vmx_vmwrite(VMCS_GUEST_VMX_PREEMPTION_TIMER_VALUE, cpu->preemption_timer);

  cpu->ctx = nullptr;

  return false;
}

// Is this the (continuation, host_exception_info) pair a guarded operation
// installs? The continuation is a label inside this image and the info lives
// on the kernel stack, so both have to look like that and nothing else.
static bool plausible_guard(uint64_t const continuation, uint64_t const info) {
  static uint64_t image_base{};
  static uint64_t image_end{};
  if (!image_base) {
    auto const raw = reinterpret_cast<const uint8_t*>(&__ImageBase);
    auto const base = reinterpret_cast<uint64_t>(raw);
    uint64_t size = 0x100000;
    auto const dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw);
    if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
      auto const nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(raw + dos->e_lfanew);
      if (nt->Signature == IMAGE_NT_SIGNATURE)
        size = nt->OptionalHeader.SizeOfImage;
    }
    image_base = base;
    image_end = base + size;
  }
  if (info < 0xffff000000000000ull) return false;
  return continuation >= image_base && continuation < image_end;
}

// called for every host interrupt
void handle_host_interrupt(trap_frame* const frame) {
  switch (frame->vector) {
  // host NMIs
  case nmi: {
    auto ctrl = read_ctrl_proc_based();
    ctrl.nmi_window_exiting = 1;
    write_ctrl_proc_based(ctrl);

    auto const cpu = reinterpret_cast<vcpu*>(_readfsbase_u64());
    ++cpu->queued_nmis;

    break;
  }
  // host exceptions
  default: {
    // The guarded operations (rdmsr_safe and friends) redirect the fault into
    // a continuation inside this image by writing r10, with r11 pointing at
    // the host_exception_info to fill in. Nothing else sets those registers,
    // so anywhere else they hold whatever the compiler left in them, and
    // honouring them jumps to a garbage address with the guest context still
    // loaded - memory corruption instead of a crash. Require a handler that
    // those wrappers could really have installed.
    if (!plausible_guard(frame->r10, frame->r11)) {
      record_root_fault(frame->vector, frame->error, frame->rip, frame->rsp,
                        frame->r10, frame->r11);
      fatal_root_error();
    }

    // jump to the exception handler
    frame->rip = frame->r10;

    auto const e = reinterpret_cast<host_exception_info*>(frame->r11);

    e->exception_occurred = true;
    e->vector             = frame->vector;
    e->error              = frame->error;

    // slightly helps prevent infinite exceptions
    frame->r10 = 0;
    frame->r11 = 0;
  }
  }
}


// reason bits, in the order they are tested below
enum diagnostic_reason : uint32_t {
  reason_vendor          = 1u << 0,
  reason_max_leaf        = 1u << 1,
  reason_vmx_bit         = 1u << 2,
  reason_xsave           = 1u << 3,
  reason_hypervisor      = 1u << 4,
  reason_fsgsbase        = 1u << 5,
  reason_cr4_la57        = 1u << 6,
  reason_cr4_cet_enforced = 1u << 7,
  reason_cr4_vmxe        = 1u << 8,
  reason_feature_control = 1u << 9,
  reason_basic_memtype   = 1u << 10,
  reason_basic_vmcs_size = 1u << 11,
  reason_basic_addrwidth = 1u << 12,
  reason_ept_cap         = 1u << 13,
  reason_proc_based      = 1u << 14,
  reason_pin_based       = 1u << 15,
  reason_secondary       = 1u << 16,
};

void diagnose_cpu(uint32_t index, cpu_diagnostic* out) {
  *out = {};
  out->index = index;
  uint32_t reasons = 0;

  int r[4]{};
  __cpuid(r, 0);
  out->max_leaf = static_cast<uint32_t>(r[0]);
  if (r[1] != 0x756e6547 || r[3] != 0x49656e69 || r[2] != 0x6c65746e) reasons |= reason_vendor;
  if (static_cast<uint32_t>(r[0]) < 0x0d) reasons |= reason_max_leaf;

  __cpuid(r, 1);
  out->cpuid_01_ecx = static_cast<uint32_t>(r[2]);
  if (!(r[2] & (1 << 5))) reasons |= reason_vmx_bit;
  if (!(r[2] & (1 << 26))) reasons |= reason_xsave;
  if (static_cast<uint32_t>(r[2]) & 0x80000000u) reasons |= reason_hypervisor;

  __cpuidex(r, 7, 0);
  out->cpuid_07_00_ebx = static_cast<uint32_t>(r[1]);
  if (!(r[1] & 1)) reasons |= reason_fsgsbase;

  out->cr4 = __readcr4();
  if (out->cr4 & (1ull << 12)) reasons |= reason_cr4_la57;
  if ((out->cr4 & (1ull << 23)) && (__readmsr(IA32_S_CET) & IA32_S_CET_SH_STK_EN_FLAG))
    reasons |= reason_cr4_cet_enforced;
  if (out->cr4 & (1ull << 13)) reasons |= reason_cr4_vmxe;

  out->feature_control = __readmsr(IA32_FEATURE_CONTROL);
  if ((out->feature_control & 5) != 5) reasons |= reason_feature_control;

  out->vmx_basic = __readmsr(IA32_VMX_BASIC);
  if (((out->vmx_basic >> 50) & 15) != 6) reasons |= reason_basic_memtype;
  if (((out->vmx_basic >> 32) & 0x1fff) > 4096) reasons |= reason_basic_vmcs_size;
  if (out->vmx_basic & (1ull << 48)) reasons |= reason_basic_addrwidth;

  out->ept_vpid_cap = __readmsr(IA32_VMX_EPT_VPID_CAP);
  constexpr auto required = (1ull << 0) | (1ull << 6) | (1ull << 14) | (1ull << 16) |
                            (1ull << 20) | (1ull << 26) | (1ull << 32) | (1ull << 41) |
                            (1ull << 42) | (1ull << 43);
  if ((out->ept_vpid_cap & required) != required) reasons |= reason_ept_cap;

  const bool true_controls = (out->vmx_basic & (1ull << 55)) != 0;
  out->proc_based_ctls = __readmsr(true_controls ? IA32_VMX_TRUE_PROCBASED_CTLS
                                                 : IA32_VMX_PROCBASED_CTLS);
  if (((out->proc_based_ctls >> 32) & ((1ull << 27) | (1ull << 28) | (1ull << 31))) !=
      ((1ull << 27) | (1ull << 28) | (1ull << 31)))
    reasons |= reason_proc_based;

  out->pin_based_ctls = __readmsr(true_controls ? IA32_VMX_TRUE_PINBASED_CTLS
                                                : IA32_VMX_PINBASED_CTLS);
  if (((out->pin_based_ctls >> 32) & 0x28) != 0x28) reasons |= reason_pin_based;

  out->secondary_ctls = __readmsr(IA32_VMX_PROCBASED_CTLS2);
  if (((out->secondary_ctls >> 32) & 0x22) != 0x22) reasons |= reason_secondary;

  out->cpuid_07_00_ecx = [] { int v[4]{}; __cpuidex(v, 7, 0); return static_cast<uint64_t>(static_cast<uint32_t>(v[2])); }();
  out->entry_ctls = __readmsr(true_controls ? IA32_VMX_TRUE_ENTRY_CTLS : IA32_VMX_ENTRY_CTLS);
  out->exit_ctls = __readmsr(true_controls ? IA32_VMX_TRUE_EXIT_CTLS : IA32_VMX_EXIT_CTLS);
  // CET is the check that keeps failing on Windows 11: record the state that
  // decides whether root mode would actually execute with a live shadow stack.
  if (out->cpuid_07_00_ecx & (1u << 7)) {
    out->cet_u_cet = __readmsr(IA32_U_CET);
    out->cet_s_cet = __readmsr(IA32_S_CET);
    out->pl0_ssp = __readmsr(IA32_PL0_SSP);
    out->pl3_ssp = __readmsr(IA32_PL3_SSP);
    out->interrupt_ssp_table = __readmsr(IA32_INTERRUPT_SSP_TABLE_ADDR);
  }

  out->reasons = reasons;
}

bool supported_cpu() {
  int r[4]; __cpuid(r, 0);
  if (r[1] != 0x756e6547 || r[3] != 0x49656e69 || r[2] != 0x6c65746e || r[0] < 0x0d) return false;
  __cpuid(r, 1);
  if (!(r[2] & (1 << 5)) || !(r[2] & (1 << 26)) || (static_cast<unsigned>(r[2]) & 0x80000000u)) return false;
  __cpuidex(r, 7, 0); if (!(r[1] & 1)) return false; // FSGSBASE
  auto const cr4 = __readcr4();
  if (cr4 & ((1ull << 12) | (1ull << 13))) return false; // LA57, already VMX
  // CR4.CET is not the same thing as an enforced shadow stack: Windows 11
  // sets the bit by default on every CET capable CPU, while IA32_S_CET
  // decides whether supervisor shadow stacks are actually pushed and
  // checked. Root mode runs at CPL0, so an enforced shadow stack would
  // fault on the first return of ours, but an idle one is inert: the CET
  // state is shared by root and guest (the VMCS CET load controls stay
  // clear, so no transition touches IA32_S_CET or the shadow stack pointer)
  // and nothing checks it. Only the enforced case is a hard failure.
  if (cr4 & (1ull << 23)) {
    if (__readmsr(IA32_S_CET) & IA32_S_CET_SH_STK_EN_FLAG) return false;
  }
  auto feature = __readmsr(IA32_FEATURE_CONTROL);
  if ((feature & 5) != 5) return false;
  auto basic = __readmsr(IA32_VMX_BASIC);
  if (((basic >> 50) & 15) != 6 || ((basic >> 32) & 0x1fff) > 4096 || (basic & (1ull << 48))) return false;
  auto ept = __readmsr(IA32_VMX_EPT_VPID_CAP);
  constexpr auto required = (1ull<<0)|(1ull<<6)|(1ull<<14)|(1ull<<16)|(1ull<<20)|(1ull<<26)|(1ull<<32)|(1ull<<41)|(1ull<<42)|(1ull<<43);
  if ((ept & required) != required) return false;
  auto primary = __readmsr((basic & (1ull<<55)) ? IA32_VMX_TRUE_PROCBASED_CTLS : IA32_VMX_PROCBASED_CTLS) >> 32;
  if ((primary & ((1ull<<27)|(1ull<<28)|(1ull<<31))) != ((1ull<<27)|(1ull<<28)|(1ull<<31))) return false;
  auto pin = __readmsr((basic & (1ull<<55)) ? IA32_VMX_TRUE_PINBASED_CTLS : IA32_VMX_PINBASED_CTLS) >> 32;
  if ((pin & 0x28) != 0x28) return false;
  auto secondary = __readmsr(IA32_VMX_PROCBASED_CTLS2) >> 32;
  if ((secondary & 0x22) != 0x22) return false;
  return true;
}

// virtualize the specified cpu. this assumes that execution is already
// restricted to the desired logical proocessor.
bool virtualize_cpu(vcpu* const cpu) {
  cpu->original_cr0 = __readcr0();
  cpu->original_cr4 = __readcr4();
  cache_cpu_data(cpu->cached);
  prepare_external_structures(cpu);
  if (!prepare_ept(cpu->ept)) return false;
  auto irql = KeRaiseIrqlToDpcLevel();
  _disable();
  auto rollback = [&] {
    __writecr0(cpu->original_cr0);
    __writecr4(cpu->original_cr4);
    _enable();
    KeLowerIrql(irql);
  };
  if (!enable_vmx_operation(cpu)) { rollback(); return false; }
  if (!enter_vmx_operation(cpu->vmxon)) { rollback(); return false; }
  if (!load_vmcs_pointer(cpu->vmcs)) { vmx_vmxoff(); rollback(); return false; }
  write_vmcs_ctrl_fields(cpu);
  write_vmcs_host_fields(cpu);
  write_vmcs_guest_fields();
  if (!vm_launch()) { vmx_vmxoff(); rollback(); return false; }
  // Back in non-root operation at DISPATCH_LEVEL on the same logical processor.
  cpu->launched = true;
  _enable();
  KeLowerIrql(irql);
  return true;
}

[[noreturn]] void fatal_root_error() {
  // Root mode runs with a private CR3, a zeroed GS base and its own GDT, IDT
  // and TSS (see write_vmcs_host_fields), so the crash path cannot run in that
  // state: its first fault or interrupt (an IST delivery, for instance) would
  // triple fault and reset the machine, losing all evidence.
  //
  // Put the guest's context back first - every value is in the VMCS, and the
  // guest's descriptor tables are valid in any address space - then let the OS
  // write a dump. A plain halt loop would leave no evidence at all.
  _disable();
  // Everything the recovery needs has to come out of the VMCS before VMXOFF.
  auto const guest_cr3 = vmx_vmread(VMCS_GUEST_CR3);
  auto const guest_gs = vmx_vmread(VMCS_GUEST_GS_BASE);
  auto const guest_fs = vmx_vmread(VMCS_GUEST_FS_BASE);
  auto const guest_rip = vmx_vmread(VMCS_GUEST_RIP);
  auto const guest_tr = static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_TR_SELECTOR));
  segment_descriptor_register_64 gdtr{};
  gdtr.base_address = vmx_vmread(VMCS_GUEST_GDTR_BASE);
  gdtr.limit = static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_GDTR_LIMIT));
  segment_descriptor_register_64 idtr{};
  idtr.base_address = vmx_vmread(VMCS_GUEST_IDTR_BASE);
  idtr.limit = static_cast<uint16_t>(vmx_vmread(VMCS_GUEST_IDTR_LIMIT));
  vmx_vmxoff();
  // The bugcheck has to run in the kernel's own address space. The guest CR3
  // is only that when the guest happened to be in kernel mode: under KVA shadow
  // a user-mode exit leaves the user CR3, which does not map the kernel pool
  // this stack lives in. Writing it back and letting the panic path push would
  // triple fault the machine instead of writing a dump - the black screens with
  // no dump at all. The system CR3 saved at startup is the kernel's, and the
  // guest descriptor tables and GS base are valid in any address space.
  __writecr3(ghv.system_cr3.flags);
  __writemsr(IA32_GS_BASE, guest_gs);
  __writemsr(IA32_FS_BASE, guest_fs);
  _lgdt(&gdtr);
  __lidt(&idtr);
  write_tr(guest_tr);
  // MANUALLY_INITIATED_CRASH (0xE2) with a private tag and where we gave up.
  KeBugCheckEx(0x000000E2, 0x424C4F4F4Bull, guest_rip, guest_cr3, guest_gs);
  for (;;) __halt();
}} // namespace hv
