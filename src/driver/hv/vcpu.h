#pragma once
#include "guest-context.h"
#include "gdt.h"
#include "idt.h"
#include "ept.h"
#include "timing.h"
#include "vmx.h"
namespace hv {
inline constexpr size_t host_stack_size = 0x8000;
inline constexpr uint16_t guest_vpid = 1;
struct vcpu_cached_data {
    uint64_t max_phys_addr{};
    uint64_t vmx_cr0_fixed0{}, vmx_cr0_fixed1{}, vmx_cr4_fixed0{}, vmx_cr4_fixed1{};
    uint64_t xcr0_unsupported_mask{};
    ia32_feature_control_register feature_control{};
    ia32_vmx_misc_register vmx_misc{};
    cpuid_eax_01 cpuid_01{};

    // Optional controls the processor accepted, filled in once the vmcs is
    // loaded so the fields they guard are never written blindly.
    bool preemption_timer_supported{};
    bool perf_global_ctrl_supported{};
};
struct vcpu {
    alignas(4096) ::vmxon vmxon;
    alignas(4096) ::vmcs vmcs;
    alignas(4096) vmx_msr_bitmap msr_bitmap;
    alignas(4096) uint8_t host_stack[host_stack_size];
    alignas(4096) segment_descriptor_interrupt_gate_64 host_idt[host_idt_descriptor_count];
    alignas(4096) segment_descriptor_32 host_gdt[host_gdt_descriptor_count];
    alignas(4096) task_state_segment_64 host_tss;
    vcpu_ept_data ept;

    // The guest view of APERF, MPERF and PERF_GLOBAL_CTRL is snapshotted on
    // vm-exit and restored on vm-entry so root mode cannot perturb the
    // counters a guest may be using to detect a world switch.
    struct alignas(16) {
        vmx_msr_entry tsc;
        vmx_msr_entry perf_global_ctrl;
        vmx_msr_entry aperf;
        vmx_msr_entry mperf;
    } msr_exit_store;
    struct alignas(16) {
        vmx_msr_entry aperf;
        vmx_msr_entry mperf;
    } msr_entry_load;

    vcpu_cached_data cached;
    guest_context* ctx{};
    uint32_t volatile queued_nmis{};
    uint64_t tsc_offset{};
    uint64_t preemption_timer{~0ull};
    uint64_t vm_exit_tsc_overhead{};
    uint64_t vm_exit_mperf_overhead{};
    uint64_t vm_exit_ref_tsc_overhead{};
    bool hide_vm_exit_overhead{};
    bool stop_virtualization{};
    bool launched{};
    uint64_t original_cr0{}, original_cr4{};
};
bool virtualize_cpu(vcpu* cpu);
bool supported_cpu();

// Bring-up diagnostic: records why the capability preflight rejected a logical
// processor, together with the raw values the decision was based on, so a
// failure can be explained without attaching a kernel debugger. The meaning
// of each bit in cpu_diagnostic::reasons is listed in vcpu.cpp next to
// diagnose_cpu().
inline constexpr uint32_t diagnostic_record_capacity = 64;
struct cpu_diagnostic {
    uint32_t index{};
    uint32_t reasons{};
    uint64_t cr4{};
    uint64_t feature_control{};
    uint64_t vmx_basic{};
    uint64_t ept_vpid_cap{};
    uint64_t proc_based_ctls{};
    uint64_t pin_based_ctls{};
    uint64_t secondary_ctls{};
    uint64_t cpuid_01_ecx{};
    uint64_t cpuid_07_00_ebx{};
    uint64_t max_leaf{};
    uint64_t cpuid_07_00_ecx{};
    uint64_t entry_ctls{};
    uint64_t exit_ctls{};
    uint64_t cet_s_cet{};
    uint64_t cet_u_cet{};
    uint64_t pl0_ssp{};
    uint64_t pl3_ssp{};
    uint64_t interrupt_ssp_table{};
};
void diagnose_cpu(uint32_t index, cpu_diagnostic* out);
[[noreturn]] void fatal_root_error();
}
