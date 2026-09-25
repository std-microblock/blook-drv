#pragma once
#include <ntifs.h>
#include "page-tables.h"
#include "policy/hook.hpp"
namespace hv {
inline constexpr uint64_t hypervisor_signature = 0x424c4f4f4b4856ull;
struct hypervisor {
    struct host_page_tables host_page_tables;
    cr3 system_cr3;
    unsigned long vcpu_count{};
    struct vcpu** vcpus{};
    bool running{};
};
extern hypervisor ghv;

// Bring-up diagnostic. `skip_instruction()` advances the guest RIP by
// VMCS_VMEXIT_INSTRUCTION_LENGTH; if the processor reports a value that does
// not match the instruction that caused the exit, the guest resumes in the
// middle of an instruction. This records what was reported for every class of
// control-register exit so the question can be settled with data instead of a
// guess. Indexed by the VMX exit qualification's access type:
// 0 = MOV to CR, 1 = MOV from CR, 2 = CLTS, 3 = LMSW.
struct cr_exit_stats {
    uint64_t count[4]{};
    uint64_t length_mask[4]{};
    uint64_t max_length[4]{};
    uint64_t decoded{};              // instructions read back and decoded
    uint64_t decoded_mismatch{};     // decoded length != reported length
    uint64_t decoded_failed{};       // could not be read or decoded
};
extern cr_exit_stats cr_stats;

// Bring-up diagnostic (service value PageFaultTrace, REG_DWORD, default off).
//
// The remaining bring-up crash starts with a guest kernel exception that
// should not happen, and a triage dump cannot show it. With this switch on the
// hypervisor intercepts the *fault* class exceptions, keeps the first-hand
// evidence in the ring buffer below, and delivers exactly the same exception
// to the guest as before (same vector, same error code, no instruction skip:
// every vector in the bitmap is a fault, so the guest RIP already points at
// the instruction the processor would report).
//
// The buffer lives in the driver (non-paged pool), so a kernel memory dump
// contains it and `dt blook_drv!fault_trace` shows it afterwards.
inline constexpr uint32_t fault_trace_count = 64;
// Page faults only for now: they are the vector the bring-up crashes show, and
// every additional intercepted vector is another chance to get the reflection
// wrong. #PF is a fault, so nothing has to be skipped when it is delivered.
inline constexpr uint32_t fault_trace_exception_bitmap = (1u << 14);  // #PF
struct fault_trace_record {
    uint64_t sequence{};
    uint64_t rip{};
    uint64_t cr2{};
    uint64_t cr3{};
    uint64_t error{};
    // Root mode runs with GS base 0, so the recording code must not call any
    // kernel API that reads the KPCR (KeGetCurrentProcessorNumber among them).
    // The vcpu pointer identifies the logical processor instead.
    uint64_t vcpu{};
    uint32_t vector{};
    uint32_t type{};           // interruption type reported by the vm-exit info
    // Raw IDT-vectoring information: non-zero valid bit means the guest was in
    // the middle of delivering another event when this one was raised, which is
    // the case the double-fault synthesis exists for.
    uint32_t idt_vectoring{};
    uint32_t double_fault{};   // 1 when this fault was turned into a #DF
};
extern fault_trace_record fault_trace[fault_trace_count];
extern volatile uint64_t fault_trace_total;
// Bring-up diagnostic: `skip_instruction` has to pick a length for the
// instruction that caused the exit. Two sources exist: the value the processor
// reports in VMCS_VMEXIT_INSTRUCTION_LENGTH, which was measured to be wrong on
// this machine (3.7M control-register exits reported length 3 and length 35),
// and the length decoded from the guest instruction bytes. Every case where
// the two disagree, and every case where the decode failed so the reported
// value had to be used anyway, is recorded here. A wrong length resumes the
// guest in the middle of an instruction or past the end of it, and that is
// exactly what the unexplained kernel pool corruption looks like. The ring is
// written to the service key on a clean stop and is visible in a kernel dump
// as `dt blook_drv!length_mismatches`.
inline constexpr uint32_t length_mismatch_capacity = 32;
struct length_mismatch_record {
    uint64_t sequence{};
    uint64_t rip{};
    uint64_t exit_qualification{};
    uint32_t decoded{};          // 0 when the decode failed
    uint32_t reported{};         // VMCS_VMEXIT_INSTRUCTION_LENGTH
    uint32_t exit_reason{};      // VMCS_EXIT_REASON, low 16 bits
    uint32_t access_type{};      // MOV CR access type when applicable
    uint8_t bytes[24]{};
};
extern length_mismatch_record length_mismatches[length_mismatch_capacity];

// Bring-up diagnostic: a root-mode exception outside a guarded operation
// (rdmsr_safe and friends) is redirected by the fault stub through r10 (a
// continuation inside this image) and r11 (the host_exception_info to fill
// in). Nothing else sets those registers, so on every other path they hold
// whatever the compiler left in them: honouring them blindly jumps to a
// garbage address with the guest context still loaded, which corrupts memory
// instead of crashing. Such a fault is now recorded here and turned into a
// bugcheck, so the faulting instruction can be found in a dump
// (dt blook_drv!hv::root_faults) or in the service key after a clean stop.
inline constexpr uint32_t root_fault_capacity = 16;
struct root_fault_record {
    uint64_t sequence{};
    uint64_t rip{};
    uint64_t rsp{};
    uint64_t r10{};
    uint64_t r11{};
    uint32_t vector{};
    uint32_t error{};
};
extern root_fault_record root_faults[root_fault_capacity];
extern volatile uint64_t root_fault_total;

inline void record_root_fault(uint32_t const vector, uint32_t const error,
                              uint64_t const rip, uint64_t const rsp,
                              uint64_t const r10, uint64_t const r11) {
    auto const total = ++root_fault_total;
    if (total > root_fault_capacity) return;
    auto& record = root_faults[total - 1];
    record.sequence = total;
    record.rip = rip;
    record.rsp = rsp;
    record.r10 = r10;
    record.r11 = r11;
    record.vector = vector;
    record.error = error;
}
extern volatile uint64_t length_mismatch_total;

// Called from vm-exit (root mode): no kernel API, no allocation, bounded work.
inline void record_length_mismatch(uint64_t const rip, uint64_t const qualification,
                                   uint32_t const decoded, uint32_t const reported,
                                   uint32_t const exit_reason, uint32_t const access_type,
                                   uint8_t const* const bytes, uint32_t const count) {
    auto const total = ++length_mismatch_total;
    if (total > length_mismatch_capacity) return;
    auto& record = length_mismatches[total - 1];
    record.sequence = total;
    record.rip = rip;
    record.exit_qualification = qualification;
    record.decoded = decoded;
    record.reported = reported;
    record.exit_reason = exit_reason;
    record.access_type = access_type;
    for (uint32_t i = 0; i < sizeof(record.bytes) && i < count; ++i)
        record.bytes[i] = bytes[i];
}

// Read once from PASSIVE_LEVEL during startup (never from vm-exit context).
void initialize_fault_trace();
bool fault_trace_enabled();
// 1 = record and reflect, 2 = reflect only (bisecting the diagnostic itself).
bool fault_trace_records();
// Lifecycle and broadcast APIs require PASSIVE_LEVEL and external serialization.
[[nodiscard]] NTSTATUS start();
void stop();
[[nodiscard]] bool install(const blook::hook_spec& spec);
void remove(uint64_t id);
void refresh(uint64_t id);
// Call-original window. These deliberately do NOT broadcast: a window is only
// meaningful on the logical processor that is running the hook handler, and
// the promise is "the page the handler is about to call into is unpatched on
// this processor until the matching end call".
bool begin_window(uint64_t id);
bool end_window(uint64_t id);

}
