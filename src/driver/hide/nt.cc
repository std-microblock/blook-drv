#include "nt.hpp"

#include <ntifs.h>
#include <intrin.h>

#include "driver/hooks.hpp"
#include "driver/resources.hpp"
#include "driver/hide/nt_types.hpp"
#include "driver/hide/peb.hpp"
#include "driver/hide/roles.hpp"
#include "policy/hook.hpp"

namespace blook::hide::nt {
namespace {
using query_system_information_t = NTSTATUS (*)(ULONG, PVOID, ULONG, PULONG);
using query_information_process_t = NTSTATUS (*)(HANDLE, PROCESSINFOCLASS,
                                                 PVOID, ULONG, PULONG);
using set_information_thread_t = NTSTATUS (*)(HANDLE, THREADINFOCLASS, PVOID,
                                              ULONG);
using query_information_thread_t = NTSTATUS (*)(HANDLE, THREADINFOCLASS, PVOID,
                                                ULONG, PULONG);
using get_context_thread_t = NTSTATUS (*)(HANDLE, PCONTEXT);
using open_process_t = NTSTATUS (*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                    PCLIENT_ID);
using open_thread_t = NTSTATUS (*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                   PCLIENT_ID);
using debug_active_process_t = NTSTATUS (*)(HANDLE, HANDLE);
using write_virtual_memory_t = NTSTATUS (*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);


// A hooked service: the id is what the handler hands to the call-original
// window, `original` is the untouched entry point of the real service.
template <class FunctionPointer>
struct service {
    uint64_t id{};
    FunctionPointer original{};
};

service<query_system_information_t> query_system_information;
service<query_information_process_t> query_information_process;
service<set_information_thread_t> set_information_thread;
service<query_information_thread_t> query_information_thread;
service<get_context_thread_t> get_context_thread;
service<open_process_t> open_process;
service<open_thread_t> open_thread;
service<debug_active_process_t> debug_active_process;
service<write_virtual_memory_t> write_virtual_memory;

// Scoped call-original window. While it is alive the hooked page exposes the
// untouched original on this processor, so `original` can be called directly.
class window final {
    uint64_t id_;
    bool pinned_{};

   public:
    explicit window(uint64_t id) : id_(id) {
        if (!id_)
            return;
        // The window is per logical processor, and a preempted thread can be
        // resumed somewhere else with the patch live again on that processor -
        // the handler would then re-enter itself. Pin the thread for the
        // duration of the call so the window stays valid.
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
            const auto mask = KAFFINITY{1} << KeGetCurrentProcessorNumber();
            KeSetSystemAffinityThread(mask);
            pinned_ = true;
        }
        if (!begin_hook_window(id_)) {
            if (pinned_) {
                KeRevertToUserAffinityThread();
                pinned_ = false;
            }
            id_ = 0;
        }
    }
    // Only a successfully opened window makes the hooked page execute the
    // untouched bytes instead of the patch. Calling the original without it
    // re-enters this handler, i.e. an unbounded recursion that ends in a
    // kernel stack overflow (seen as a 0x3B in SwapContext/NtQuerySystem*).
    explicit operator bool() const { return id_ != 0; }
    ~window() {
        if (id_)
            end_hook_window(id_);
        if (pinned_)
            KeRevertToUserAffinityThread();
    }
    window(const window&) = delete;
    window& operator=(const window&) = delete;
};

// Opens the call-original window and invokes the real service through it.
// install() publishes the id and the entry point before the patch is armed,
// so an unresolved service is not a path a handler normally sees - the check
// keeps a partially installed hook from ever calling address zero. This is
// not a theoretical concern: doing exactly that bugchecked the machine.
template <class FunctionPointer, class... Args>
NTSTATUS call_original(const service<FunctionPointer>& svc, Args... args) {
    const auto original = svc.original;
    if (!svc.id || !original)
        return STATUS_DEVICE_NOT_READY;
    window guard{svc.id};
    if (!guard)
        return STATUS_DEVICE_NOT_READY;
    return original(args...);
}

// A debugger that starts the sample with DEBUG_PROCESS has BeingDebugged set
// while the process is created, before any hook of ours can run. The first
// service the sample calls is therefore the moment to clear it, once per
// process.
EX_PUSH_LOCK scrub_lock{};
uint32_t scrubbed[16]{};

bool first_contact(uint32_t pid) {
    exclusive_lock lock{scrub_lock};
    const auto slot = pid % (sizeof(scrubbed) / sizeof(scrubbed[0]));
    if (scrubbed[slot] == pid) return false;
    scrubbed[slot] = pid;
    return true;
}

void scrub_on_first_contact() {
    if (!roles::is_target()) return;
    auto* process = PsGetCurrentProcess();
    const auto pid = static_cast<uint32_t>(
        reinterpret_cast<uintptr_t>(PsGetProcessId(process)));
    if (pid && first_contact(pid)) peb::process(process, peb::scrub_flags);
}

// NtWriteVirtualMemory
//
// Clearing the flag once is not enough: a debugger that attaches later writes
// it again. The write is not refused outright - the flag byte is neutralised
// in the caller buffer for the duration of the call, so every other byte of a
// multi byte write still lands where the tool wanted it.
struct flag_patch {
    uint8_t* byte{};
    uint8_t saved{};
};

flag_patch neutralise_flag_byte(HANDLE process_handle, PVOID base, PVOID buffer, SIZE_T size) {
    flag_patch result;
    if (!base || !buffer || !size) return result;
    PEPROCESS process{};
    if (!NT_SUCCESS(ObReferenceObjectByHandle(process_handle, 0, *PsProcessType,
            ExGetPreviousMode(), reinterpret_cast<PVOID*>(&process), nullptr)))
        return result;
    // Tools may write to themselves; only the sample is protected.
    if (roles::of_process(process) == role::tool) {
        ObDereferenceObject(process);
        return result;
    }
    __try {
        const auto peb = reinterpret_cast<uint64_t>(PsGetProcessPeb(process));
        const auto address = reinterpret_cast<uint64_t>(base);
        const auto flag = peb + 2;
        if (peb && address <= flag && address + size > flag) {
            auto* byte = static_cast<uint8_t*>(buffer) + (flag - address);
            if (*byte) {
                result.byte = byte;
                result.saved = *byte;
                *byte = 0;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = {};
    }
    ObDereferenceObject(process);
    return result;
}

NTSTATUS hook_write_virtual_memory(HANDLE process_handle, PVOID base, PVOID buffer,
                                   SIZE_T size, PSIZE_T written) {
    flag_patch patch;
    if (roles::is_tool() && ExGetPreviousMode() == UserMode)
        patch = neutralise_flag_byte(process_handle, base, buffer, size);
    const auto status = call_original(write_virtual_memory, process_handle,
                                      base, buffer, size, written);
    if (patch.byte) {
        __try { *patch.byte = patch.saved; }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    return status;
}

// User-mode outputs are written through a guard: the syscall validated them,
// but a handler must not be the reason an invalid pointer turns into a fault.
template <class T>
bool write_user(PVOID destination, T value) {
    if (!destination)
        return false;
    __try {
        *static_cast<T*>(destination) = value;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

void strip_processes(PVOID buffer, PULONG return_length) {
    if (!return_length)
        return;
    const auto used = *return_length;
    if (used < sizeof(system_process_entry))
        return;
    auto* base = static_cast<uint8_t*>(buffer);

    // One pass: move every surviving entry down over the holes the hidden ones
    // left, and relink the chain with the new distances as we go. The old code
    // relinked in a second pass that still walked with the *old* distances,
    // which after compaction lands on unrelated bytes and rewrites their
    // NextEntryOffset - the caller then walks a corrupted list.
    ULONG read = 0;
    ULONG write = 0;
    ULONG previous = 0;
    bool have_previous = false;
    __try {
    while (read + sizeof(system_process_entry) <= used) {
        auto* node = reinterpret_cast<system_process_entry*>(base + read);
        const ULONG offset = node->next_entry_offset;
        const ULONG size = offset ? offset : (used - read);
        if (size < sizeof(system_process_entry) || read + size > used)
            break;
        if (offset && (offset & 3))
            break;

        bool hidden = false;
        if (node->image_name.Buffer && node->image_name.Length) {
            const auto length = node->image_name.Length / sizeof(wchar_t);
            // The name pointer inside the entry is a user-mode pointer that the
            // service already validated; the length is not trusted further than
            // this bound before it is walked.
            if (length < 32768)
                hidden =
                    blook::classify(node->image_name.Buffer, length) == role::tool;
        }
        hidden = hidden ||
                 roles::pinned_role(static_cast<uint32_t>(
                     reinterpret_cast<uintptr_t>(node->unique_process_id))) ==
                     role::tool;

        if (!hidden) {
            if (write != read)
                memmove(base + write, node, size);
            if (have_previous)
                reinterpret_cast<system_process_entry*>(base + previous)
                    ->next_entry_offset = write - previous;
            previous = write;
            have_previous = true;
            write += size;
        }
        if (!offset)
            break;
        read += size;
    }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Best effort: leave the list as the service produced it.
        return;
    }

    if (write == 0) {
        // Nothing survived: report a single anonymous entry rather than a chain
        // the caller would walk into stale bytes.
        auto* node = reinterpret_cast<system_process_entry*>(base);
        node->image_name.Length = 0;
        node->image_name.MaximumLength = 0;
        node->unique_process_id = nullptr;
        node->next_entry_offset = 0;
        return;
    }

    reinterpret_cast<system_process_entry*>(base + previous)->next_entry_offset = 0;
    *return_length = write;
}

void strip_modules(PVOID buffer, ULONG length) {
    if (!buffer || length < sizeof(rtl_process_modules))
        return;
    auto* modules = static_cast<rtl_process_modules*>(buffer);
    const auto capacity = static_cast<ULONG>(
        (length - offsetof(rtl_process_modules, modules)) /
        sizeof(rtl_process_module_information));
    __try {
        ULONG index = 0;
        while (index < modules->number_of_modules && index < capacity) {
            const auto* path = reinterpret_cast<const char*>(
                modules->modules[index].full_path_name);
            size_t name_length = 0;
            while (name_length < 256 && path[name_length])
                ++name_length;
            if (!hidden_module(path, name_length)) {
                ++index;
                continue;
            }
            const auto remaining = modules->number_of_modules - index - 1;
            if (remaining)
                memmove(&modules->modules[index], &modules->modules[index + 1],
                        remaining * sizeof(rtl_process_module_information));
            --modules->number_of_modules;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // A malformed entry must never turn into a fault in the handler.
    }
}

void hide_kernel_debugger(PVOID buffer, ULONG length) {
    if (length < sizeof(system_kernel_debugger_information))
        return;
    auto* info = static_cast<system_kernel_debugger_information*>(buffer);
    info->enabled = FALSE;
    info->not_present = TRUE;
}

bool read_client_id(PCLIENT_ID client_id, uint32_t& pid, uint32_t& tid) {
    pid = tid = 0;
    if (!client_id)
        return false;
    __try {
        pid = static_cast<uint32_t>(
            reinterpret_cast<uintptr_t>(client_id->UniqueProcess));
        tid = static_cast<uint32_t>(
            reinterpret_cast<uintptr_t>(client_id->UniqueThread));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

bool tool_thread(uint32_t tid) {
    if (!tid || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return false;
    PETHREAD thread{};
    if (!NT_SUCCESS(PsLookupThreadByThreadId(ULongToHandle(tid), &thread)))
        return false;
    bool tool = false;
    if (auto* process = PsGetThreadProcess(thread))
        tool = roles::of_process(process) == role::tool;
    ObDereferenceObject(thread);
    return tool;
}

// Bring-up probe: what does the processor state look like at the moment the
// patch hands control to this handler? The entry jump is a ret, so [rsp] must
// hold the address the caller pushed; the arguments must look like
// (class, buffer, length, return_length). If they do not, the hook fired
// somewhere other than a call boundary - which is what puts service output on
// an unrelated kernel stack. Kept in the driver's own memory so a dump shows
// it (the array is deliberately named for that).
struct handler_probe_record {
    uint64_t sequence;
    uint64_t return_slot;
    uint64_t slot1;
    uint64_t slot2;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    // Filled just before the handler returns: if these differ from the entry
    // sample, the call damaged its own return slot / frame.
    uint64_t return_slot_after;
    uint64_t slot1_after;
    uint64_t slot2_after;
    uint64_t rsp_after;
};
handler_probe_record handler_probes[32]{};
volatile uint64_t handler_probe_total{};

NTSTATUS hook_query_system_information_impl(ULONG info_class, PVOID buffer,
                                       ULONG length, PULONG return_length) {
    {
        auto const total = ++handler_probe_total;
        if (total <= 32) {
            auto& probe = handler_probes[total - 1];
            auto* const return_slot =
                static_cast<uint64_t*>(_AddressOfReturnAddress());
            probe.sequence = total;
            probe.return_slot = return_slot ? return_slot[0] : 0;
            probe.slot1 = return_slot ? return_slot[1] : 0;
            probe.slot2 = return_slot ? return_slot[2] : 0;
            probe.arg0 = info_class;
            probe.arg1 = reinterpret_cast<uint64_t>(buffer);
            probe.arg2 = length;
            probe.arg3 = reinterpret_cast<uint64_t>(return_length);
        }
    }

    // Bring-up knob HideNoCall=0: the hook still fires and the handler still
    // runs, but the original service is never entered. If the machine survives
    // with this, the crash lives in the call-original path; if it still dies,
    // the crash is in the hook firing / page view switching itself.
    if (!service_mask_allows(L"HideNoCall", 0))
        return STATUS_DEVICE_NOT_READY;

    const auto status = call_original(query_system_information, info_class,
                                      buffer, length, return_length);
    // The analyst always sees the real machine; only the sample is filtered.
    scrub_on_first_contact();
    if (!NT_SUCCESS(status) || !buffer || roles::is_tool())
        return status;

    // Bring-up knob: HideRewrite=0 keeps the profile (the hook still fires and
    // calls the original) but does not touch the returned data. Bisecting the
    // rewriting away from the hook mechanism is what this exists for.
    if (!service_mask_allows(L"HideRewrite", 0))
        return status;

    switch (static_cast<system_information_class>(info_class)) {
        case system_information_class::process:
            strip_processes(buffer, return_length);
            break;
        case system_information_class::module:
            strip_modules(buffer, length);
            break;
        case system_information_class::kernel_debugger:
            hide_kernel_debugger(buffer, length);
            break;
        default:
            break;
    }
    return status;
}

// Sampling wrapper: the same picture the entry probe takes, taken again right
// before the handler returns. A difference in the return slot is the direct
// evidence that this call path is eating its own way back to the caller.
// A nested entry is normal here: NtQuerySystemInformation and
// NtQuerySystemInformationEx call each other, so with a correct trampoline the
// nesting depth is exactly the depth the unhooked function has. Guarding it out
// broke the service (callers retried forever) - that was the last hang.
//
// What must never happen instead is the trampoline jumping back *into* the
// patched range: its target has to be the instruction boundary right after the
// bytes it replayed.
NTSTATUS hook_query_system_information(ULONG info_class, PVOID buffer,
                                       ULONG length, PULONG return_length) {
    auto* const return_slot = static_cast<uint64_t*>(_AddressOfReturnAddress());
    auto const before_0 = return_slot ? return_slot[0] : 0;
    auto const before_1 = return_slot ? return_slot[1] : 0;
    auto const before_2 = return_slot ? return_slot[2] : 0;
    auto const status =
        hook_query_system_information_impl(info_class, buffer, length, return_length);
    auto const after_0 = return_slot ? return_slot[0] : 0;
    auto const after_1 = return_slot ? return_slot[1] : 0;
    auto const after_2 = return_slot ? return_slot[2] : 0;
    for (uint64_t i = 0; i < 32; ++i) {
        auto& probe = handler_probes[i];
        if (probe.sequence != 0 && probe.return_slot == before_0 &&
            probe.arg0 == info_class &&
            probe.arg2 == length && probe.return_slot_after == 0) {
            probe.return_slot_after = after_0;
            probe.slot1_after = after_1;
            probe.slot2_after = after_2;
            probe.rsp_after = reinterpret_cast<uint64_t>(return_slot);
            break;
        }
    }
    return status;
}

NTSTATUS hook_query_information_process(HANDLE process_handle,
                                        PROCESSINFOCLASS info_class, PVOID info,
                                        ULONG length, PULONG return_length) {
    const bool spoof = roles::is_target() && ExGetPreviousMode() == UserMode;
    scrub_on_first_contact();
    const auto status = call_original(query_information_process,
                                      process_handle, info_class, info, length,
                                      return_length);
    if (!spoof || !NT_SUCCESS(status))
        return status;

    switch (info_class) {
        case ProcessDebugPort:
            if (length >= sizeof(HANDLE)) {
                write_user<HANDLE>(info, nullptr);
                if (return_length)
                    write_user<ULONG>(return_length, sizeof(HANDLE));
            }
            break;
        case ProcessDebugObjectHandle:
            // The not-debugged answer is a failure, so the caller cannot be
            // told there is a debug object even if one exists.
            if (length >= sizeof(HANDLE))
                write_user<HANDLE>(info, nullptr);
            return STATUS_PORT_NOT_SET;
        case ProcessDebugFlags:
            if (length >= sizeof(ULONG)) {
                write_user<ULONG>(info, 1);
                if (return_length)
                    write_user<ULONG>(return_length, sizeof(ULONG));
            }
            break;
        default:
            break;
    }
    return status;
}

NTSTATUS hook_set_information_thread(HANDLE thread_handle,
                                     THREADINFOCLASS info_class, PVOID info,
                                     ULONG length) {
    // Refusing the request keeps the thread visible to the debugger instead of
    // letting the sample hide the threads the analyst needs to inspect.
    if (info_class == ThreadHideFromDebugger && roles::is_target())
        return STATUS_SUCCESS;
    return call_original(set_information_thread, thread_handle, info_class,
                         info, length);
}

NTSTATUS hook_query_information_thread(HANDLE thread_handle,
                                       THREADINFOCLASS info_class, PVOID info,
                                       ULONG length, PULONG return_length) {
    const auto status = call_original(query_information_thread, thread_handle,
                                      info_class, info, length, return_length);
    if (!NT_SUCCESS(status) || !roles::is_target())
        return status;
    if (info_class == ThreadHideFromDebugger && length >= sizeof(ULONG))
        write_user<ULONG>(info, 0);
    return status;
}

NTSTATUS hook_get_context_thread(HANDLE thread_handle, PCONTEXT context) {
    const auto status =
        call_original(get_context_thread, thread_handle, context);
    if (!NT_SUCCESS(status) || !context || !roles::is_target())
        return status;
    // Hardware breakpoints belong to the debugger. A sample that reads its own
    // thread context must not find them.
    __try {
        if (context->ContextFlags & 0x00100000 /* CONTEXT_DEBUG_REGISTERS */) {
            context->Dr0 = 0;
            context->Dr1 = 0;
            context->Dr2 = 0;
            context->Dr3 = 0;
            context->Dr6 = 0;
            context->Dr7 = 0;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return status;
}

NTSTATUS hook_open_process(PHANDLE process_handle, ACCESS_MASK access,
                           POBJECT_ATTRIBUTES attributes,
                           PCLIENT_ID client_id) {
    uint32_t pid{}, tid{};
    if (read_client_id(client_id, pid, tid) && roles::is_target() && pid &&
        roles::pid_is_tool(pid))
        return STATUS_ACCESS_DENIED;
    return call_original(open_process, process_handle, access, attributes,
                         client_id);
}

NTSTATUS hook_open_thread(PHANDLE thread_handle, ACCESS_MASK access,
                          POBJECT_ATTRIBUTES attributes, PCLIENT_ID client_id) {
    uint32_t pid{}, tid{};
    if (read_client_id(client_id, pid, tid) && roles::is_target() &&
        tool_thread(tid))
        return STATUS_ACCESS_DENIED;
    return call_original(open_thread, thread_handle, access, attributes,
                         client_id);
}

NTSTATUS hook_debug_active_process(HANDLE process_handle, HANDLE debug_object) {
    const auto status =
        call_original(debug_active_process, process_handle, debug_object);
    // Attaching a debugger is exactly the moment Windows sets BeingDebugged and
    // the debug heap flags, so undo it right away.
    if (NT_SUCCESS(status)) {
        PEPROCESS process{};
        if (NT_SUCCESS(ObReferenceObjectByHandle(
                process_handle, 0, *PsProcessType, ExGetPreviousMode(),
                reinterpret_cast<PVOID*>(&process), nullptr))) {
            peb::process(process, peb::scrub_flags);
            ObDereferenceObject(process);
        }
    }
    return status;
}

struct install_entry {
    uint64_t* id;
    void** original;
    const wchar_t* symbol;
    void* handler;
};

install_entry entries[] = {
    {&query_system_information.id,
     reinterpret_cast<void**>(&query_system_information.original),
     L"NtQuerySystemInformation",
     reinterpret_cast<void*>(&hook_query_system_information)},
    {&query_information_process.id,
     reinterpret_cast<void**>(&query_information_process.original),
     L"NtQueryInformationProcess",
     reinterpret_cast<void*>(&hook_query_information_process)},
    {&set_information_thread.id,
     reinterpret_cast<void**>(&set_information_thread.original),
     L"NtSetInformationThread",
     reinterpret_cast<void*>(&hook_set_information_thread)},
    {&query_information_thread.id,
     reinterpret_cast<void**>(&query_information_thread.original),
     L"NtQueryInformationThread",
     reinterpret_cast<void*>(&hook_query_information_thread)},
    {&get_context_thread.id,
     reinterpret_cast<void**>(&get_context_thread.original),
     L"NtGetContextThread", reinterpret_cast<void*>(&hook_get_context_thread)},
    {&open_process.id, reinterpret_cast<void**>(&open_process.original),
     L"NtOpenProcess", reinterpret_cast<void*>(&hook_open_process)},
    {&open_thread.id, reinterpret_cast<void**>(&open_thread.original),
     L"NtOpenThread", reinterpret_cast<void*>(&hook_open_thread)},
    {&debug_active_process.id,
     reinterpret_cast<void**>(&debug_active_process.original),
     L"NtDebugActiveProcess",
     reinterpret_cast<void*>(&hook_debug_active_process)},
    {&write_virtual_memory.id,
     reinterpret_cast<void**>(&write_virtual_memory.original),
     L"NtWriteVirtualMemory", reinterpret_cast<void*>(&hook_write_virtual_memory)},
};
}  // namespace

void forget_process(ULONG pid) {
    if (!pid) return;
    exclusive_lock lock{scrub_lock};
    for (auto& value : scrubbed)
        if (value == pid) value = 0;
}

bool installed() {
    for (const auto& entry : entries)
        if (*entry.id)
            return true;
    return false;
}

NTSTATUS install() {
    uint32_t count = 0;
    for (uint32_t index = 0; index < sizeof(entries) / sizeof(entries[0]); ++index) {
        auto& entry = entries[index];
        if (*entry.id) {
            ++count;
            continue;
        }
        // Bring-up knob (see service_mask_allows): HookMask selects which
        // services this pass may arm.
        if (!service_mask_allows(L"HookMask", index)) {
            blook::bringup_write("install: masked out, index", index, true);
            continue;
        }
        UNICODE_STRING symbol;
        RtlInitUnicodeString(&symbol, entry.symbol);
        auto* address = MmGetSystemRoutineAddress(&symbol);
        // A service that is not exported on this build is skipped rather than
        // guessed at.
        if (!address) {
            blook::bringup_write("install: name unresolved, index", index, true);
            continue;
        }
        // prepare_hook builds the patch: only it knows the literal slot.
        uint8_t patch[max_patch]{};
        // Register and publish first, arm second. The handler needs both the
        // id (for its call-original window) and the entry point, and it can
        // be reached from another processor as soon as its own processor is
        // armed.
        prepared_hook prepared{};
        const auto prepared_status = prepare_hook(0, system_token, address, patch,
                                                  jump_patch_length, prepared,
                                                  entry.handler);
        blook::bringup_write("install: prepare status", static_cast<uint32_t>(prepared_status), true);
        if (!NT_SUCCESS(prepared_status))
            continue;

        // Without a trampoline the handler could only reach the original by
        // calling the patched entry, which re-enters the handler without
        // bound. Skip the hook instead.
        if (!prepared.trampoline) {
            blook::bringup_write("install: no trampoline, index", index, true);
            cancel_hook(prepared);
            continue;
        }
        *entry.id = prepared.id;
        // The trampoline is the copy of the overwritten bytes: reaching the
        // original means running those bytes and jumping back into the
        // function. No page view is touched for that.
        *entry.original = prepared.trampoline ? prepared.trampoline : address;
        if (NT_SUCCESS(arm_hook(prepared))) {
            ++count;
            continue;
        }
        *entry.id = 0;
        *entry.original = nullptr;
    }
    return count ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
}

void remove() {
    for (auto& entry : entries) {
        if (!*entry.id)
            continue;
        remove_hook(*entry.id);
        *entry.id = 0;
        *entry.original = nullptr;
    }
}
}  // namespace blook::hide::nt
