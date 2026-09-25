#include "hv.h"

#include "driver/hooks.hpp"
#include "timing.h"
#include "vcpu.h"
namespace hv {
hypervisor ghv{};
cr_exit_stats cr_stats{};
fault_trace_record fault_trace[fault_trace_count]{};
volatile uint64_t fault_trace_total{};
length_mismatch_record length_mismatches[length_mismatch_capacity]{};
volatile uint64_t length_mismatch_total{};
root_fault_record root_faults[root_fault_capacity]{};
volatile uint64_t root_fault_total{};
namespace {
uint32_t fault_trace_level{};
}  // namespace

void initialize_fault_trace() {
    // PageFaultTrace: 0/absent = off, 1 = record + reflect, 2 = reflect only.
    uint32_t level{};
    UNICODE_STRING path = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\BlookDrv");
    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr,
                               nullptr);
    HANDLE key{};
    if (NT_SUCCESS(ZwOpenKey(&key, KEY_QUERY_VALUE, &attributes))) {
        struct {
            KEY_VALUE_PARTIAL_INFORMATION information;
            uint8_t data[64];
        } buffer{};
        UNICODE_STRING name = RTL_CONSTANT_STRING(L"PageFaultTrace");
        ULONG length{};
        if (NT_SUCCESS(ZwQueryValueKey(key, &name, KeyValuePartialInformation,
                                       &buffer, sizeof(buffer), &length)) &&
            buffer.information.Type == REG_DWORD &&
            buffer.information.DataLength >= sizeof(uint32_t))
            level = *reinterpret_cast<const uint32_t*>(buffer.information.Data);
        ZwClose(key);
    }
    fault_trace_level = level;
}

bool fault_trace_enabled() { return fault_trace_level != 0; }
bool fault_trace_records() { return fault_trace_level == 1; }
namespace {
class affinity_guard final {
    GROUP_AFFINITY previous_{};
public:
    explicit affinity_guard(ULONG index) {
        PROCESSOR_NUMBER number{};
        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(index, &number))) KeBugCheckEx(DRIVER_CORRUPTED_EXPOOL, index, 0, 0, 0);
        GROUP_AFFINITY affinity{};
        affinity.Group = number.Group;
        affinity.Mask = KAFFINITY{1} << number.Number;
        KeSetSystemGroupAffinityThread(&affinity, &previous_);
    }
    ~affinity_guard() { KeRevertToUserGroupAffinityThread(&previous_); }
    affinity_guard(const affinity_guard&) = delete;
};
}
namespace {
void write_registry_value(const wchar_t* name, const void* data, uint32_t bytes) {
    if (!data || !bytes) return;
    auto* blob = static_cast<uint8_t*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, 'dlkB'));
    if (!blob) return;
    for (uint32_t i = 0; i < bytes; ++i) blob[i] = static_cast<const uint8_t*>(data)[i];
    RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\BlookDrv",
        const_cast<wchar_t*>(name), REG_BINARY, blob, bytes);
    ExFreePoolWithTag(blob, 'dlkB');
}

// Bring-up diagnostic: a flat blob in the driver service key,
// [magic, record_count, vcpu_count, record_size] followed by one
// cpu_diagnostic per logical processor.
void write_preflight_report(cpu_diagnostic const* report, uint32_t stored, uint32_t vcpu_count) {
    if (!report || !stored) return;
    constexpr uint32_t header_words = 4;
    const auto bytes = header_words * sizeof(uint32_t) + stored * sizeof(cpu_diagnostic);
    auto* blob = static_cast<uint32_t*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, 'dlkB'));
    if (!blob) return;
    blob[0] = 0x4b4c4250;
    blob[1] = stored;
    blob[2] = vcpu_count;
    blob[3] = static_cast<uint32_t>(sizeof(cpu_diagnostic));
    for (uint32_t i = 0; i < stored; ++i)
        reinterpret_cast<cpu_diagnostic*>(&blob[header_words])[i] = report[i];
    RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\BlookDrv",
        L"Preflight", REG_BINARY, blob, bytes);
    ExFreePoolWithTag(blob, 'dlkB');
}
}

NTSTATUS start() {
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (ghv.running) return STATUS_SUCCESS;
    // Anything the hypervisor consults per vm-exit has to be resolved here,
    // while the IRQL is known to be PASSIVE_LEVEL.
    initialize_timing_switch();
    initialize_fault_trace();
    ghv.vcpu_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (!ghv.vcpu_count) return STATUS_NOT_SUPPORTED;
    // Bring-up instrumentation: record what every logical processor reports
    // before the preflight so a rejection can be explained afterwards.
    {
        const auto capacity = diagnostic_record_capacity;
        auto* report = static_cast<cpu_diagnostic*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(cpu_diagnostic) * capacity, 'dlkB'));
        if (report) {
            const ULONG count = ghv.vcpu_count < capacity ? ghv.vcpu_count : capacity;
            for (ULONG i = 0; i < count; ++i) {
                affinity_guard affinity{i};
                diagnose_cpu(i, &report[i]);
            }
            write_preflight_report(report, count, ghv.vcpu_count);
            ExFreePoolWithTag(report, 'dlkB');
        }
    }
    // Preflight ALL processors before starting any VM. Rollback must be possible.
    for (ULONG i = 0; i < ghv.vcpu_count; ++i) {
        affinity_guard affinity{i};
        if (!supported_cpu()) { ghv.vcpu_count = 0; return STATUS_HV_FEATURE_UNAVAILABLE; }
    }
    auto ranges = MmGetPhysicalMemoryRanges();
    if (!ranges) return STATUS_INSUFFICIENT_RESOURCES;
    bool fits = true;
    for (size_t i = 0; ranges[i].NumberOfBytes.QuadPart; ++i)
        if (static_cast<uint64_t>(ranges[i].BaseAddress.QuadPart + ranges[i].NumberOfBytes.QuadPart) > physical_limit) fits = false;
    ExFreePool(ranges);
    if (!fits) { ghv.vcpu_count = 0; return STATUS_NOT_SUPPORTED; }
    ghv.vcpus = static_cast<vcpu**>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(vcpu*) * ghv.vcpu_count, 'vklB'));
    if (!ghv.vcpus) { ghv.vcpu_count = 0; return STATUS_INSUFFICIENT_RESOURCES; }
    for (ULONG i = 0; i < ghv.vcpu_count; ++i) {
        ghv.vcpus[i] = static_cast<vcpu*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(vcpu), 'pklB'));
        if (!ghv.vcpus[i]) { stop(); return STATUS_INSUFFICIENT_RESOURCES; }
    }
    KAPC_STATE state{};
    KeStackAttachProcess(PsInitialSystemProcess, &state);
    ghv.system_cr3.flags = __readcr3();
    prepare_host_page_tables();
    KeUnstackDetachProcess(&state);
    for (ULONG i = 0; i < ghv.vcpu_count; ++i) {
        affinity_guard affinity{i};
        if (!virtualize_cpu(ghv.vcpus[i])) { stop(); return STATUS_UNSUCCESSFUL; }
    }
    // Measure the cost of a world switch so it can be removed from the guest
    // clock. This runs after this processor is virtualised, so the VMCALLs
    // inside the measurement perform a real non-root to root round trip.
    const auto tsc_overhead   = measure_vm_exit_tsc_overhead();
    const auto mperf_overhead = measure_vm_exit_mperf_overhead();
    const auto ref_overhead   = measure_vm_exit_ref_tsc_overhead();
    for (ULONG i = 0; i < ghv.vcpu_count; ++i) {
        ghv.vcpus[i]->vm_exit_tsc_overhead     = tsc_overhead;
        ghv.vcpus[i]->vm_exit_mperf_overhead   = mperf_overhead;
        ghv.vcpus[i]->vm_exit_ref_tsc_overhead = ref_overhead;
    }
    ghv.running = true;
    return STATUS_SUCCESS;
}
void stop() {
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    // Publish the control-register exit statistics before tearing down: this
    // is the only report that needs the hypervisor to have been running.
    write_registry_value(L"CrExitStats", &cr_stats, sizeof(cr_stats));
    // Same for the fault trace: readable after a clean stop as well as from a
    // kernel dump (dt blook_drv!fault_trace) when the machine did not survive.
    uint64_t trace_total = fault_trace_total;
    write_registry_value(L"FaultTrace", fault_trace, sizeof(fault_trace));
    write_registry_value(L"FaultTraceTotal", &trace_total, sizeof(trace_total));
    // Same for the instruction-length decisions: this is the evidence a crash
    // cannot erase, and the only report that says whether the length the
    // processor reported and the length decoded from the guest bytes agreed.
    {
        uint64_t mismatch_total = length_mismatch_total;
        write_registry_value(L"LengthMismatches", length_mismatches, sizeof(length_mismatches));
        write_registry_value(L"LengthMismatchTotal", &mismatch_total, sizeof(mismatch_total));
    }
    {
        uint64_t root_total = root_fault_total;
        write_registry_value(L"RootFaults", root_faults, sizeof(root_faults));
        write_registry_value(L"RootFaultTotal", &root_total, sizeof(root_total));
    }
    if (ghv.vcpus) {
        for (ULONG i = 0; i < ghv.vcpu_count; ++i) {
            auto cpu = ghv.vcpus[i];
            if (!cpu || !cpu->launched) continue;
            affinity_guard affinity{i};
            hypercall_input input{operation::stop};
            if (vmx_vmcall(input) != 1) KeBugCheckEx(DRIVER_CORRUPTED_EXPOOL, 0x424c, i, 0, 0);
            cpu->launched = false;
        }
        for (ULONG i = 0; i < ghv.vcpu_count; ++i) if (ghv.vcpus[i]) ExFreePoolWithTag(ghv.vcpus[i], 'pklB');
        ExFreePoolWithTag(ghv.vcpus, 'vklB');
        ghv.vcpus = nullptr;
    }
    ghv.vcpu_count = 0;
    ghv.running = false;
}
bool install(const blook::hook_spec& spec) {
    if (!ghv.running) return false;
    for (ULONG i = 0; i < ghv.vcpu_count; ++i) {
        affinity_guard affinity{i};
        hypercall_input input{operation::install};
        input.args[0] = reinterpret_cast<uint64_t>(&spec);
        if (!vmx_vmcall(input)) {
            // Roll back every CPU already changed, before freeing any pinned pages.
            remove(spec.id);
            return false;
        }
    }
    return true;
}
void refresh(uint64_t id) {
    if (!ghv.running) return;
    for (ULONG i = 0; i < ghv.vcpu_count; ++i) {
        affinity_guard affinity{i};
        hypercall_input input{operation::refresh}; input.args[0] = id;
        if (vmx_vmcall(input) != 1) KeBugCheckEx(DRIVER_CORRUPTED_EXPOOL, 0x424e, i, id, 0);
    }
}
namespace {
// A call-original window has to be in effect on every logical processor, not
// only on the one that opened it: the hook handler runs inside a normal guest
// thread, and nothing stops the scheduler from preempting that thread and
// resuming it somewhere else while the window is open. On that processor the
// hooked page would still carry the patch, the call into the original would
// land on the hook again, and the handler would re-enter itself - which walks
// the thread stack into unrelated memory (this is what turned into executions
// of linker padding and into pool corruption).
//
// Broadcasting needs the affinity APIs, so it is only done at PASSIVE_LEVEL;
// a handler that runs higher keeps the old single-processor behaviour instead
// of faulting in the affinity call.
bool broadcast_window(operation op, uint64_t id) {
    // Single logical processor only. An earlier version broadcast the window to
    // every processor, which ran affinity changes and migrated this thread in
    // the middle of the hooked system service; that is a hazard of its own. The
    // handler stays on the processor it is already running on for the duration
    // of the call instead (see hide::nt::window), so this is enough.
    if (!ghv.running) return false;
    hypercall_input input{op};
    input.args[0] = id;
    return vmx_vmcall(input) == 1;
}
}  // namespace

bool begin_window(uint64_t id) { return broadcast_window(operation::window_begin, id); }
bool end_window(uint64_t id) { return broadcast_window(operation::window_end, id); }
void remove(uint64_t id) {
    if (!ghv.running) return;
    for (ULONG i = 0; i < ghv.vcpu_count; ++i) {
        affinity_guard affinity{i};
        hypercall_input input{operation::remove}; input.args[0] = id;
        if (vmx_vmcall(input) != 1) KeBugCheckEx(DRIVER_CORRUPTED_EXPOOL, 0x424d, i, id, 0);
    }
}
}
