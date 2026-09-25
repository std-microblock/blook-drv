// Adapted from jonomango/hv (MIT); see LICENSES/jonomango-hv.txt.
//
// A guest can tell it is virtualised by timing an instruction whose cost is
// normally a few cycles. When that instruction is intercepted, the world
// switch dominates the measurement. The TSC offset mechanism lets the guest
// see a continuous clock that excludes the time spent in root mode, and the
// preemption timer bounds how far the offset is allowed to drift before it is
// resynchronised.
#include "timing.h"

#include <intrin.h>

#include "driver/hooks.hpp"
#include "hypercalls.h"
#include "vcpu.h"
#include "vmx.h"

namespace hv {
namespace {
uint64_t smallest_of(uint64_t a, uint64_t b) {
    return a < b ? a : b;
}

uint64_t ping_round_trip() {
    hypercall_input input{operation::ping};
    return vmx_vmcall(input);
}

}  // namespace

// Bring-up switch: HKLM\SYSTEM\CurrentControlSet\Services\BlookDrv\HideTiming=0
// disables TSC offsetting and the performance counter compensation. That
// compensation is what makes an intercepted instruction look untimed, but it
// also edits guest visible monotonic counters (TSC, APERF/MPERF,
// IA32_FIXED_CTR2), which is the most invasive thing this hypervisor does to
// a running system. With the switch off the counters are simply passed
// through, at the cost of being detectable by timing.
namespace {
bool timing_hidden_cached{true};
}  // namespace

void initialize_timing_switch() {
    // Read the switch once, from PASSIVE_LEVEL during startup. timing_hidden()
    // is consulted from vm-exit context at whatever IRQL the guest had, and
    // touching the registry from there is a guaranteed IRQL_NOT_LESS_OR_EQUAL
    // (that is exactly how the first version of this switch crashed).
    timing_hidden_cached = blook::service_mask_allows(L"HideTiming", 0);
}

bool timing_hidden() { return timing_hidden_cached; }


void hide_vm_exit_overhead(vcpu* const cpu) {
    if (!timing_hidden()) {
        cpu->tsc_offset = 0;
        cpu->preemption_timer = ~0ull;
        return;
    }
    ia32_perf_global_ctrl_register perf_global_ctrl;
    perf_global_ctrl.flags = cpu->msr_exit_store.perf_global_ctrl.msr_data;

    // Make the processor reload the snapshot taken on this exit.
    cpu->msr_entry_load.aperf.msr_data = cpu->msr_exit_store.aperf.msr_data;
    cpu->msr_entry_load.mperf.msr_data = cpu->msr_exit_store.mperf.msr_data;
    vmx_vmwrite(VMCS_GUEST_PERF_GLOBAL_CTRL, perf_global_ctrl.flags);

    // Account for the constant cost of the MSR loads and stores themselves.
    cpu->msr_entry_load.aperf.msr_data -= cpu->vm_exit_mperf_overhead;
    cpu->msr_entry_load.mperf.msr_data -= cpu->vm_exit_mperf_overhead;

    if (perf_global_ctrl.en_fixed_ctrn & (1ull << 2)) {
        const auto cpl = current_guest_cpl();

        ia32_fixed_ctr_ctrl_register fixed_ctr_ctrl;
        fixed_ctr_ctrl.flags = __readmsr(IA32_FIXED_CTR_CTRL);

        const bool counting = (cpl == 0 && fixed_ctr_ctrl.en2_os) ||
                              (cpl == 3 && fixed_ctr_ctrl.en2_usr);
        if (counting)
            __writemsr(IA32_FIXED_CTR2, __readmsr(IA32_FIXED_CTR2) -
                                            cpu->vm_exit_ref_tsc_overhead);
    }

    // Exits we cannot attribute to a single instruction (exceptions, NMI
    // delivery, preemption) are the chance to resynchronise the clock, since
    // hiding their cost would accumulate error instead of removing it.
    if (!cpu->hide_vm_exit_overhead || cpu->vm_exit_tsc_overhead > 10000) {
        cpu->tsc_offset = 0;
        cpu->preemption_timer = ~0ull;
        return;
    }

    // Force a resynchronisation after roughly 10000 guest TSC ticks.
    const auto shift = cpu->cached.vmx_misc.preemption_timer_tsc_relationship;
    uint64_t ticks = uint64_t{10000} >> shift;
    if (ticks < 2)
        ticks = 2;
    cpu->preemption_timer = ticks;

    cpu->tsc_offset -= cpu->vm_exit_tsc_overhead;
}

uint64_t measure_vm_exit_tsc_overhead() {
    _disable();

    uint64_t lowest_exit = ~0ull;
    uint64_t lowest_timing = ~0ull;

    for (int i = 0; i < 10; ++i) {
        _mm_lfence();
        auto start = __rdtsc();
        _mm_lfence();
        _mm_lfence();
        auto end = __rdtsc();
        _mm_lfence();
        const auto timing = end - start;

        ping_round_trip();

        _mm_lfence();
        start = __rdtsc();
        _mm_lfence();
        ping_round_trip();
        _mm_lfence();
        end = __rdtsc();
        _mm_lfence();
        const auto exit = end - start;

        lowest_exit = smallest_of(exit, lowest_exit);
        lowest_timing = smallest_of(timing, lowest_timing);
    }

    _enable();
    return lowest_exit - lowest_timing;
}

uint64_t measure_vm_exit_mperf_overhead() {
    _disable();

    uint64_t lowest_exit = ~0ull;
    uint64_t lowest_timing = ~0ull;

    for (int i = 0; i < 10; ++i) {
        _mm_lfence();
        auto start = __readmsr(IA32_MPERF);
        _mm_lfence();
        _mm_lfence();
        auto end = __readmsr(IA32_MPERF);
        _mm_lfence();
        const auto timing = end - start;

        ping_round_trip();

        _mm_lfence();
        start = __readmsr(IA32_MPERF);
        _mm_lfence();
        ping_round_trip();
        _mm_lfence();
        end = __readmsr(IA32_MPERF);
        _mm_lfence();
        const auto exit = end - start;

        lowest_exit = smallest_of(exit, lowest_exit);
        lowest_timing = smallest_of(timing, lowest_timing);
    }

    _enable();
    return lowest_exit - lowest_timing;
}

uint64_t measure_vm_exit_ref_tsc_overhead() {
    _disable();

    ia32_fixed_ctr_ctrl_register saved_ctrl;
    saved_ctrl.flags = __readmsr(IA32_FIXED_CTR_CTRL);

    ia32_perf_global_ctrl_register saved_global;
    saved_global.flags = __readmsr(IA32_PERF_GLOBAL_CTRL);

    auto ctrl = saved_ctrl;
    ctrl.en2_os = 1;
    ctrl.en2_usr = 0;
    ctrl.en2_pmi = 0;
    ctrl.any_thread2 = 0;
    __writemsr(IA32_FIXED_CTR_CTRL, ctrl.flags);

    auto global = saved_global;
    global.en_fixed_ctrn |= (1ull << 2);
    __writemsr(IA32_PERF_GLOBAL_CTRL, global.flags);

    uint64_t lowest_exit = ~0ull;
    uint64_t lowest_timing = ~0ull;

    for (int i = 0; i < 10; ++i) {
        _mm_lfence();
        auto start = __readmsr(IA32_FIXED_CTR2);
        _mm_lfence();
        _mm_lfence();
        auto end = __readmsr(IA32_FIXED_CTR2);
        _mm_lfence();
        const auto timing = end - start;

        ping_round_trip();

        _mm_lfence();
        start = __readmsr(IA32_FIXED_CTR2);
        _mm_lfence();
        ping_round_trip();
        _mm_lfence();
        end = __readmsr(IA32_FIXED_CTR2);
        _mm_lfence();
        const auto exit = end - start;

        lowest_exit = smallest_of(exit, lowest_exit);
        lowest_timing = smallest_of(timing, lowest_timing);
    }

    __writemsr(IA32_PERF_GLOBAL_CTRL, saved_global.flags);
    __writemsr(IA32_FIXED_CTR_CTRL, saved_ctrl.flags);

    _enable();
    return lowest_exit - lowest_timing;
}
}  // namespace hv
