#include "peb.hpp"

#include <ntifs.h>

#include "driver/resources.hpp"

// The PEB is user-mode memory, so it is edited while attached to the process
// that owns it. Every field write below is guarded: a word is only modified
// when it already looks like the artefact it is supposed to be, so a layout
// change can never turn this into an arbitrary memory write.
namespace blook::peb {
namespace {
// Native x64 PEB. BeingDebugged and NtGlobalFlag have been at these offsets
// since the first x64 build of Windows; the heap offsets are the ones the
// debug heap itself and al-khaser both use.
constexpr size_t peb_being_debugged = 0x02;
constexpr size_t peb_nt_global_flag = 0xbc;
constexpr size_t peb_process_heap = 0x30;
constexpr size_t peb_wow64_nt_global_flag = 0x68;
constexpr size_t heap_flags = 0x70;
constexpr size_t heap_force_flags = 0x74;
constexpr uint32_t debug_flag_mask = 0x70;
constexpr uint32_t debug_force_flag_mask = 0x40000060;

template <class T>
bool read_field(void* base, size_t offset, T& value) {
    if (!base)
        return false;
    __try {
        value = *reinterpret_cast<T*>(static_cast<uint8_t*>(base) + offset);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

template <class T>
bool write_field(void* base, size_t offset, T value) {
    if (!base)
        return false;
    __try {
        *reinterpret_cast<T*>(static_cast<uint8_t*>(base) + offset) = value;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

void scrub_peb(void* peb, bool wow64) {
    if (!peb)
        return;
    auto* bytes = static_cast<uint8_t*>(peb);
    if (bytes[peb_being_debugged] != 0)
        write_field(bytes, peb_being_debugged, uint8_t{0});

    const auto global_flag_offset =
        wow64 ? peb_wow64_nt_global_flag : peb_nt_global_flag;
    uint32_t global_flag{};
    if (read_field(bytes, global_flag_offset, global_flag) &&
        (global_flag & debug_flag_mask) && !(global_flag & ~debug_flag_mask)) {
        write_field(bytes, global_flag_offset, global_flag & ~debug_flag_mask);
    }

    if (!wow64) {
        void* heap{};
        if (!read_field(bytes, peb_process_heap, heap) || !heap)
            return;
        uint32_t flags{}, force_flags{};
        if (!read_field(static_cast<uint8_t*>(heap), heap_flags, flags))
            return;
        if (!read_field(static_cast<uint8_t*>(heap), heap_force_flags,
                        force_flags))
            return;
        // Only ever touch a pair that is exactly the debug heap pattern: the
        // force flags word has no other legitimate bit set.
        if (force_flags & ~debug_force_flag_mask)
            return;
        if ((flags & debug_flag_mask) ||
            (force_flags & debug_force_flag_mask)) {
            write_field(static_cast<uint8_t*>(heap), heap_flags,
                        flags & ~debug_flag_mask);
            write_field(static_cast<uint8_t*>(heap), heap_force_flags,
                        force_flags & ~debug_force_flag_mask);
        }
    }
}

NTSTATUS scrub(PEPROCESS process, uint32_t flags) {
    if (!process)
        return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    KAPC_STATE apc{};
    NTSTATUS status = STATUS_SUCCESS;
    KeStackAttachProcess(process, &apc);
    __try {
        auto* peb = reinterpret_cast<uint8_t*>(PsGetProcessPeb(process));
        auto* wow64 =
            reinterpret_cast<uint8_t*>(PsGetProcessWow64Process(process));
        void* native_target =
            (flags & (flag_being_debugged | flag_global_flag | flag_heap))
                ? peb
                : nullptr;
        if (native_target)
            scrub_peb(native_target, false);
        if (wow64 && (flags & (flag_being_debugged | flag_global_flag)))
            scrub_peb(wow64, true);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    KeUnstackDetachProcess(&apc);
    return status;
}
}  // namespace

NTSTATUS process(PEPROCESS process, uint32_t flags) {
    return scrub(process, flags);
}

NTSTATUS process(uint32_t pid, uint32_t flags) {
    if (!pid)
        return STATUS_INVALID_PARAMETER;
    PEPROCESS process{};
    auto status = PsLookupProcessByProcessId(ULongToHandle(pid), &process);
    if (!NT_SUCCESS(status))
        return status;
    status = scrub(process, flags);
    ObDereferenceObject(process);
    return status;
}
}  // namespace blook::peb
