#pragma once

#include "policy/integer.hpp"

namespace hv {
struct vcpu;

// Measure the constant cost of a world switch so it can be subtracted from the
// guest view of the TSC and of the performance counters. Each measurement runs
// a VMCALL round trip and keeps the smallest sample.
uint64_t measure_vm_exit_tsc_overhead();
uint64_t measure_vm_exit_mperf_overhead();
uint64_t measure_vm_exit_ref_tsc_overhead();

// Called on every vm-exit before returning to the guest. Compensates the guest
// TSC for exits that only exist because the hypervisor intercepted something,
// and resynchronises the offset on exits that cannot be timed reliably.
void hide_vm_exit_overhead(vcpu* cpu);

// Service key switch (HideTiming, REG_DWORD, default on). When it is 0 the
// TSC offsetting and the performance counter compensation are skipped and the
// VMCS MSR load/store lists are left empty. Read once by
// initialize_timing_switch(); the cached answer is safe to use from vm-exit
// context.
void initialize_timing_switch();
bool timing_hidden();
}  // namespace hv
