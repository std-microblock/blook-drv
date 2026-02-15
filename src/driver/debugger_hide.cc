#include "debugger_hide.hpp"

#include <ntifs.h>
#include <windef.h>

#include "core/core.hpp"
#include "process_manager.hpp"
#include "ssdt/ssdt_hook.hpp"

// --------------------------------------------------------------------------
// Extra structures not provided by Veil or the WDK headers we include
// --------------------------------------------------------------------------

// ObjectTypesInformation returns this header followed by variable-length
// OBJECT_TYPE_INFORMATION entries. We only need the count; entries are
// walked via pointer arithmetic.
typedef struct _OBJECT_ALL_INFORMATION {
    ULONG NumberOfObjectsTypes;
    // Followed by OBJECT_TYPE_INFORMATION[] (walked manually)
} OBJECT_ALL_INFORMATION, *POBJECT_ALL_INFORMATION;

// ObjectDataInformation (info class 4)
typedef struct _OBJECT_HANDLE_ATTRIBUTE_INFORMATION {
    BOOLEAN Inherit;
    BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_ATTRIBUTE_INFORMATION, *POBJECT_HANDLE_ATTRIBUTE_INFORMATION;

// Job object process ID list (not always available in kernel headers)
typedef struct _JOBOBJECT_BASIC_PROCESS_ID_LIST_LOCAL {
    ULONG NumberOfAssignedProcesses;
    ULONG NumberOfProcessIdsInList;
    ULONG_PTR ProcessIdList[1];
} JOBOBJECT_BASIC_PROCESS_ID_LIST_LOCAL, *PJOBOBJECT_BASIC_PROCESS_ID_LIST_LOCAL;

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

namespace {

// Mutex for NtClose serialization
KMUTEX g_nt_close_mutex;

// PROCESS_DEBUG_INHERIT is not defined in Veil
constexpr ULONG PROCESS_DEBUG_INHERIT = 1;

// Filter hidden processes out of a linked SYSTEM_PROCESS_INFORMATION chain.
// Unlinks entries whose ImageName matches the hidden-process list.
void filter_process_list(PSYSTEM_PROCESS_INFORMATION head) {
    if (!head)
        return;

    PSYSTEM_PROCESS_INFORMATION prev = nullptr;
    PSYSTEM_PROCESS_INFORMATION curr = head;

    while (curr) {
        bool should_hide = false;
        if (curr->ImageName.Buffer)
            should_hide = process_manager::is_hidden(curr->ImageName.Buffer);

        if (should_hide && prev) {
            if (curr->NextEntryOffset)
                prev->NextEntryOffset += curr->NextEntryOffset;
            else
                prev->NextEntryOffset = 0;
        } else {
            prev = curr;
        }

        if (!curr->NextEntryOffset)
            break;
        curr = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
            reinterpret_cast<PUCHAR>(curr) + curr->NextEntryOffset);
    }
}

// Convert a PID to PEPROCESS (best effort, returns nullptr on failure).
PEPROCESS pid_to_eprocess(HANDLE pid) {
    PEPROCESS process = nullptr;
    if (NT_SUCCESS(PsLookupProcessByProcessId(pid, &process))) {
        ObDereferenceObject(process);  // we just want the pointer value
        return process;
    }
    return nullptr;
}

}  // anonymous namespace

// --------------------------------------------------------------------------
// Hook registration
// --------------------------------------------------------------------------

namespace debugger_hide {

core::VoidResult register_hooks() {
    KeInitializeMutex(&g_nt_close_mutex, 0);

    auto& mgr = ssdt::SsdtHookManager::instance();

    // ======================================================================
    // NtQueryInformationProcess
    // ======================================================================
    {
        auto res = mgr.hook_by_syscall_name("NtQueryInformationProcess");
        ASSERT_TRUE(res, NotFound);
        static auto& hook = res.value();
        hook << [](HANDLE ProcessHandle,
                   PROCESSINFOCLASS ProcessInformationClass,
                   PVOID ProcessInformation, ULONG ProcessInformationLength,
                   PULONG ReturnLength) -> NTSTATUS {
            auto original = hook.get_original<NtQueryInformationProcess>();

            if (!process_manager::current_is_target_ex() ||
                ExGetPreviousMode() != UserMode) {
                return original(ProcessHandle, ProcessInformationClass,
                                ProcessInformation, ProcessInformationLength,
                                ReturnLength);
            }

            // -- ProcessDebugObjectHandle --
            if (ProcessInformationClass == ProcessDebugObjectHandle) {
                if (ProcessInformationLength != sizeof(HANDLE))
                    return STATUS_INFO_LENGTH_MISMATCH;

                NTSTATUS status = original(
                    ProcessHandle, ProcessInformationClass, ProcessInformation,
                    ProcessInformationLength, ReturnLength);

                // Always report no debug object
                __try {
                    *static_cast<PHANDLE>(ProcessInformation) = nullptr;
                    if (ReturnLength)
                        *ReturnLength = sizeof(HANDLE);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return GetExceptionCode();
                }
                return STATUS_PORT_NOT_SET;
            }

            // -- ProcessDebugPort --
            if (ProcessInformationClass == ProcessDebugPort) {
                if (ProcessInformationLength != sizeof(ULONG_PTR))
                    return STATUS_INFO_LENGTH_MISMATCH;

                NTSTATUS status = original(
                    ProcessHandle, ProcessInformationClass, ProcessInformation,
                    ProcessInformationLength, ReturnLength);

                __try {
                    *static_cast<PULONG_PTR>(ProcessInformation) = 0;
                    if (ReturnLength)
                        *ReturnLength = sizeof(ULONG_PTR);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return GetExceptionCode();
                }
                return STATUS_SUCCESS;
            }

            // -- ProcessDebugFlags --
            if (ProcessInformationClass == ProcessDebugFlags) {
                if (ProcessInformationLength != sizeof(ULONG))
                    return STATUS_INFO_LENGTH_MISMATCH;

                NTSTATUS status = original(
                    ProcessHandle, ProcessInformationClass, ProcessInformation,
                    ProcessInformationLength, ReturnLength);

                __try {
                    // Report PROCESS_DEBUG_INHERIT (= "not being debugged")
                    *static_cast<PULONG>(ProcessInformation) =
                        PROCESS_DEBUG_INHERIT;
                    if (ReturnLength)
                        *ReturnLength = sizeof(ULONG);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return GetExceptionCode();
                }
                return STATUS_SUCCESS;
            }

            // -- ProcessBasicInformation --
            if (ProcessInformationClass == ProcessBasicInformation) {
                NTSTATUS status = original(
                    ProcessHandle, ProcessInformationClass, ProcessInformation,
                    ProcessInformationLength, ReturnLength);
                if (!NT_SUCCESS(status))
                    return status;

                // Spoof parent PID to explorer.exe if possible
                __try {
                    auto* pbi = static_cast<PPROCESS_BASIC_INFORMATION>(
                        ProcessInformation);
                    // Leave as-is (could spoof to explorer later)
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return GetExceptionCode();
                }
                return status;
            }

            // -- ProcessHandleTracing --
            if (ProcessInformationClass == ProcessHandleTracing) {
                // Just pass through; handle tracing state is not a debug
                // indicator worth spoofing in our simplified model.
                return original(ProcessHandle, ProcessInformationClass,
                                ProcessInformation, ProcessInformationLength,
                                ReturnLength);
            }

            // Everything else: passthrough
            return original(ProcessHandle, ProcessInformationClass,
                            ProcessInformation, ProcessInformationLength,
                            ReturnLength);
        };
        ASSERT_TRUE(hook.enable(), HookFailed);
    }

    // ======================================================================
    // NtSetInformationThread
    // ======================================================================
    {
        auto res = mgr.hook_by_syscall_name("NtSetInformationThread");
        ASSERT_TRUE(res, NotFound);
        static auto& hook = res.value();
        hook << [](HANDLE ThreadHandle,
                   THREADINFOCLASS ThreadInformationClass,
                   PVOID ThreadInformation,
                   ULONG ThreadInformationLength) -> NTSTATUS {
            auto original = hook.get_original<NtSetInformationThread>();

            if (!process_manager::current_is_target_ex() ||
                ExGetPreviousMode() != UserMode) {
                return original(ThreadHandle, ThreadInformationClass,
                                ThreadInformation, ThreadInformationLength);
            }

            // -- ThreadHideFromDebugger: silently swallow --
            if (ThreadInformationClass == ThreadHideFromDebugger) {
                if (ThreadInformationLength != 0)
                    return STATUS_INFO_LENGTH_MISMATCH;
                return STATUS_SUCCESS;
            }

            // -- ThreadBreakOnTermination: swallow --
            if (ThreadInformationClass == ThreadBreakOnTermination) {
                if (ThreadInformationLength != sizeof(ULONG))
                    return STATUS_INFO_LENGTH_MISMATCH;
                return STATUS_SUCCESS;
            }

            // -- ThreadWow64Context: strip debug registers --
            if (ThreadInformationClass == ThreadWow64Context) {
                if (ThreadInformationLength != sizeof(WOW64_CONTEXT))
                    return STATUS_INFO_LENGTH_MISMATCH;

                __try {
                    auto* ctx =
                        static_cast<PWOW64_CONTEXT>(ThreadInformation);
                    ctx->ContextFlags &= ~0x10u;  // CONTEXT_DEBUG_REGISTERS
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return GetExceptionCode();
                }

                return original(ThreadHandle, ThreadInformationClass,
                                ThreadInformation, ThreadInformationLength);
            }

            return original(ThreadHandle, ThreadInformationClass,
                            ThreadInformation, ThreadInformationLength);
        };
        ASSERT_TRUE(hook.enable(), HookFailed);
    }

    // ======================================================================
    // NtSetInformationProcess
    // ======================================================================
    {
        auto res = mgr.hook_by_syscall_name("NtSetInformationProcess");
        ASSERT_TRUE(res, NotFound);
        static auto& hook = res.value();
        hook << [](HANDLE ProcessHandle,
                   PROCESSINFOCLASS ProcessInformationClass,
                   PVOID ProcessInformation,
                   ULONG ProcessInformationLength) -> NTSTATUS {
            auto original = hook.get_original<NtSetInformationProcess>();

            if (!process_manager::current_is_target_ex() ||
                ExGetPreviousMode() != UserMode) {
                return original(ProcessHandle, ProcessInformationClass,
                                ProcessInformation, ProcessInformationLength);
            }

            // Swallow debug-related set calls
            if (ProcessInformationClass == ProcessBreakOnTermination ||
                ProcessInformationClass == ProcessDebugFlags ||
                ProcessInformationClass == ProcessHandleTracing) {
                return STATUS_SUCCESS;
            }

            return original(ProcessHandle, ProcessInformationClass,
                            ProcessInformation, ProcessInformationLength);
        };
        ASSERT_TRUE(hook.enable(), HookFailed);
    }

    // ======================================================================
    // NtQueryObject
    // ======================================================================
    {
        auto res = mgr.hook_by_syscall_name("NtQueryObject");
        ASSERT_TRUE(res, NotFound);
        static auto& hook = res.value();
        hook << [](HANDLE Handle,
                   OBJECT_INFORMATION_CLASS ObjectInformationClass,
                   PVOID ObjectInformation, ULONG ObjectInformationLength,
                   PULONG ReturnLength) -> NTSTATUS {
            auto original = hook.get_original<NtQueryObject>();
            NTSTATUS status = original(Handle, ObjectInformationClass,
                                       ObjectInformation,
                                       ObjectInformationLength, ReturnLength);

            if (!process_manager::current_is_target_ex() ||
                ExGetPreviousMode() != UserMode || !NT_SUCCESS(status) ||
                !ObjectInformation) {
                return status;
            }

            UNICODE_STRING debug_object;
            RtlInitUnicodeString(&debug_object, L"DebugObject");

            if (ObjectInformationClass == ObjectTypeInformation) {
                auto* info =
                    static_cast<POBJECT_TYPE_INFORMATION>(ObjectInformation);
                if (RtlEqualUnicodeString(&info->TypeName, &debug_object,
                                          FALSE)) {
                    if (info->TotalNumberOfObjects > 0)
                        info->TotalNumberOfObjects--;
                    if (info->TotalNumberOfHandles > 0)
                        info->TotalNumberOfHandles--;
                }
            } else if (ObjectInformationClass == ObjectTypesInformation) {
                auto* all =
                    static_cast<POBJECT_ALL_INFORMATION>(ObjectInformation);
                // First OBJECT_TYPE_INFORMATION starts right after the header
                auto* loc =
                    reinterpret_cast<PUCHAR>(all + 1);

                for (ULONG i = 0; i < all->NumberOfObjectsTypes; ++i) {
                    auto* type_info =
                        reinterpret_cast<POBJECT_TYPE_INFORMATION>(loc);

                    if (RtlEqualUnicodeString(&type_info->TypeName,
                                              &debug_object, FALSE)) {
                        if (type_info->TotalNumberOfObjects > 0)
                            type_info->TotalNumberOfObjects--;
                        if (type_info->TotalNumberOfHandles > 0)
                            type_info->TotalNumberOfHandles--;
                    }

                    // Advance to next OBJECT_TYPE_INFORMATION
                    loc = reinterpret_cast<PUCHAR>(type_info->TypeName.Buffer);
                    loc += type_info->TypeName.MaximumLength;
                    auto aligned = (reinterpret_cast<ULONG_PTR>(loc) +
                                    sizeof(PVOID) - 1) &
                                   ~(sizeof(PVOID) - 1);
                    loc = reinterpret_cast<PUCHAR>(aligned);
                }
            }

            return status;
        };
        ASSERT_TRUE(hook.enable(), HookFailed);
    }

    // ======================================================================
    // NtSystemDebugControl
    // ======================================================================
    {
        auto res = mgr.hook_by_syscall_name("NtSystemDebugControl");
        ASSERT_TRUE(res, NotFound);
        static auto& hook = res.value();
        hook << [](SYSDBG_COMMAND Command, PVOID InputBuffer,
                   ULONG InputBufferLength, PVOID OutputBuffer,
                   ULONG OutputBufferLength,
                   PULONG ReturnLength) -> NTSTATUS {
            auto original = hook.get_original<NtSystemDebugControl>();

            if (process_manager::current_is_target_ex() &&
                Command != SysDbgGetTriageDump &&
                Command != SysDbgGetLiveKernelDump) {
                return STATUS_DEBUGGER_INACTIVE;
            }

            return original(Command, InputBuffer, InputBufferLength,
                            OutputBuffer, OutputBufferLength, ReturnLength);
        };
        ASSERT_TRUE(hook.enable(), HookFailed);
    }

    // ======================================================================
    // NtClose
    // ======================================================================
    {
        auto res = mgr.hook_by_syscall_name("NtClose");
        ASSERT_TRUE(res, NotFound);
        static auto& hook = res.value();
        hook << [](HANDLE Handle) -> NTSTATUS {
            auto original = hook.get_original<NtClose>();

            if (!process_manager::current_is_target_ex())
                return original(Handle);

            // Serialize to avoid races on handle attribute queries
            KeWaitForSingleObject(&g_nt_close_mutex, Executive, KernelMode,
                                  FALSE, nullptr);

            OBJECT_HANDLE_ATTRIBUTE_INFORMATION attr{};
            NTSTATUS status = ZwQueryObject(
                Handle,
                static_cast<OBJECT_INFORMATION_CLASS>(4),  // ObjectDataInformation
                &attr, sizeof(attr), nullptr);

            if (status == STATUS_INVALID_HANDLE) {
                KeReleaseMutex(&g_nt_close_mutex, FALSE);
                return STATUS_INVALID_HANDLE;
            }

            if (NT_SUCCESS(status) && attr.ProtectFromClose) {
                KeReleaseMutex(&g_nt_close_mutex, FALSE);
                return STATUS_HANDLE_NOT_CLOSABLE;
            }

            KeReleaseMutex(&g_nt_close_mutex, FALSE);
            return original(Handle);
        };
        ASSERT_TRUE(hook.enable(), HookFailed);
    }

    // ======================================================================
    // NtQuerySystemInformation
    // ======================================================================
    {
        auto res = mgr.hook_by_syscall_name("NtQuerySystemInformation");
        ASSERT_TRUE(res, NotFound);
        static auto& hook = res.value();
        hook << [](SYSTEM_INFORMATION_CLASS SystemInformationClass,
                   PVOID SystemInformation, ULONG SystemInformationLength,
                   PULONG ReturnLength) -> NTSTATUS {
            auto original = hook.get_original<NtQuerySystemInformation>();
            NTSTATUS status =
                original(SystemInformationClass, SystemInformation,
                         SystemInformationLength, ReturnLength);

            if (!process_manager::current_is_target_ex() ||
                ExGetPreviousMode() != UserMode || !NT_SUCCESS(status)) {
                return status;
            }

            // -- SystemKernelDebuggerInformation --
            if (SystemInformationClass == SystemKernelDebuggerInformation) {
                auto* info =
                    static_cast<PSYSTEM_KERNEL_DEBUGGER_INFORMATION>(
                        SystemInformation);
                info->KernelDebuggerEnabled = FALSE;
                info->KernelDebuggerNotPresent = TRUE;
            }

            // -- SystemKernelDebuggerInformationEx --
            else if (SystemInformationClass ==
                     SystemKernelDebuggerInformationEx) {
                auto* info =
                    static_cast<PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX>(
                        SystemInformation);
                info->DebuggerAllowed = FALSE;
                info->DebuggerEnabled = FALSE;
                info->DebuggerPresent = FALSE;
            }

            // -- SystemKernelDebuggerFlags --
            else if (SystemInformationClass == SystemKernelDebuggerFlags) {
                *static_cast<PUCHAR>(SystemInformation) = 0;
            }

            // -- SystemCodeIntegrityInformation --
            else if (SystemInformationClass ==
                     SystemCodeIntegrityInformation) {
                static_cast<PSYSTEM_CODEINTEGRITY_INFORMATION>(
                    SystemInformation)
                    ->CodeIntegrityOptions = 0x01;  // ENABLED
            }

            // -- Process info classes: strip hidden processes --
            else if (SystemInformationClass == SystemProcessInformation ||
                     SystemInformationClass ==
                         SystemExtendedProcessInformation ||
                     SystemInformationClass == SystemFullProcessInformation) {
                filter_process_list(
                    static_cast<PSYSTEM_PROCESS_INFORMATION>(
                        SystemInformation));
            }

            // -- SystemSessionProcessInformation --
            else if (SystemInformationClass ==
                     SystemSessionProcessInformation) {
                auto* session =
                    static_cast<PSYSTEM_SESSION_PROCESS_INFORMATION>(
                        SystemInformation);
                filter_process_list(
                    reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
                        session->Buffer));
            }

            // -- SystemExtendedHandleInformation --
            else if (SystemInformationClass ==
                     SystemExtendedHandleInformation) {
                auto* info = static_cast<PSYSTEM_HANDLE_INFORMATION_EX>(
                    SystemInformation);

                ULONG_PTR write_idx = 0;
                for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
                    auto* entry = &info->Handles[i];
                    auto ep = pid_to_eprocess(entry->UniqueProcessId);
                    if (ep && process_manager::is_hidden(ep))
                        continue;  // skip this entry
                    if (write_idx != i)
                        info->Handles[write_idx] = info->Handles[i];
                    ++write_idx;
                }
                if (write_idx < info->NumberOfHandles) {
                    RtlSecureZeroMemory(
                        &info->Handles[write_idx],
                        sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) *
                            (info->NumberOfHandles - write_idx));
                    info->NumberOfHandles = write_idx;
                }
            }

            // -- SystemHandleInformation --
            else if (SystemInformationClass == SystemHandleInformation) {
                auto* info = static_cast<PSYSTEM_HANDLE_INFORMATION>(
                    SystemInformation);

                ULONG write_idx = 0;
                for (ULONG i = 0; i < info->NumberOfHandles; ++i) {
                    auto* entry = &info->Handles[i];
                    auto ep = pid_to_eprocess(
                        reinterpret_cast<HANDLE>(
                            static_cast<ULONG_PTR>(entry->UniqueProcessId)));
                    if (ep && process_manager::is_hidden(ep))
                        continue;
                    if (write_idx != i)
                        info->Handles[write_idx] = info->Handles[i];
                    ++write_idx;
                }
                if (write_idx < info->NumberOfHandles) {
                    RtlSecureZeroMemory(
                        &info->Handles[write_idx],
                        sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO) *
                            (info->NumberOfHandles - write_idx));
                    info->NumberOfHandles = write_idx;
                }
            }

            // -- SystemPoolTagInformation: strip our driver tag --
            else if (SystemInformationClass == SystemPoolTagInformation) {
                auto* info = static_cast<PSYSTEM_POOLTAG_INFORMATION>(
                    SystemInformation);

                ULONG write_idx = 0;
                for (ULONG i = 0; i < info->Count; ++i) {
                    ULONG tag = info->TagInfo[i].TagUlong;
                    // Strip our own pool tags
                    if (tag == 'pmgr' || tag == 'hide' || tag == 'cbkH')
                        continue;
                    if (write_idx != i)
                        info->TagInfo[write_idx] = info->TagInfo[i];
                    ++write_idx;
                }
                if (write_idx < info->Count) {
                    RtlSecureZeroMemory(
                        &info->TagInfo[write_idx],
                        sizeof(SYSTEM_POOLTAG) *
                            (info->Count - write_idx));
                    info->Count = write_idx;
                }
            }

            return status;
        };
        ASSERT_TRUE(hook.enable(), HookFailed);
    }

    // ======================================================================
    // NtSetContextThread — strip debug registers
    // ======================================================================
    {
        auto res = mgr.hook_by_syscall_name("NtSetContextThread");
        ASSERT_TRUE(res, NotFound);
        static auto& hook = res.value();
        hook << [](HANDLE ThreadHandle, PCONTEXT Context) -> NTSTATUS {
            auto original = hook.get_original<NtSetContextThread>();

            if (!process_manager::current_is_target_ex() ||
                ExGetPreviousMode() != UserMode) {
                return original(ThreadHandle, Context);
            }

            __try {
                Context->ContextFlags &= ~0x10u;  // CONTEXT_DEBUG_REGISTERS
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                return GetExceptionCode();
            }

            return original(ThreadHandle, Context);
        };
        ASSERT_TRUE(hook.enable(), HookFailed);
    }

    // ======================================================================
    // NtGetContextThread — zero debug registers
    // ======================================================================
    {
        auto res = mgr.hook_by_syscall_name("NtGetContextThread");
        ASSERT_TRUE(res, NotFound);
        static auto& hook = res.value();
        hook << [](HANDLE ThreadHandle, PCONTEXT Context) -> NTSTATUS {
            auto original = hook.get_original<NtGetContextThread>();

            if (!process_manager::current_is_target_ex() ||
                ExGetPreviousMode() != UserMode) {
                return original(ThreadHandle, Context);
            }

            __try {
                ULONG original_flags = Context->ContextFlags;
                Context->ContextFlags &= ~0x10u;

                NTSTATUS status = original(ThreadHandle, Context);

                if (original_flags & 0x10) {
                    Context->ContextFlags |= 0x10;
                    // Return zeroed debug registers
                    Context->Dr0 = 0;
                    Context->Dr1 = 0;
                    Context->Dr2 = 0;
                    Context->Dr3 = 0;
                    Context->Dr6 = 0;
                    Context->Dr7 = 0;
                    Context->DebugControl = 0;
                    Context->LastBranchToRip = 0;
                    Context->LastBranchFromRip = 0;
                    Context->LastExceptionToRip = 0;
                    Context->LastExceptionFromRip = 0;
                }

                return status;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                return GetExceptionCode();
            }
        };
        ASSERT_TRUE(hook.enable(), HookFailed);
    }

    // ======================================================================
    // NtQueryInformationThread
    // ======================================================================
    {
        auto res = mgr.hook_by_syscall_name("NtQueryInformationThread");
        ASSERT_TRUE(res, NotFound);
        static auto& hook = res.value();
        hook << [](HANDLE ThreadHandle,
                   THREADINFOCLASS ThreadInformationClass,
                   PVOID ThreadInformation, ULONG ThreadInformationLength,
                   PULONG ReturnLength) -> NTSTATUS {
            auto original = hook.get_original<NtQueryInformationThread>();

            if (!process_manager::current_is_target_ex() ||
                ExGetPreviousMode() != UserMode) {
                return original(ThreadHandle, ThreadInformationClass,
                                ThreadInformation, ThreadInformationLength,
                                ReturnLength);
            }

            // -- ThreadHideFromDebugger: always report FALSE --
            if (ThreadInformationClass == ThreadHideFromDebugger) {
                if (ThreadInformationLength != 1)
                    return STATUS_INFO_LENGTH_MISMATCH;

                __try {
                    *static_cast<PBOOLEAN>(ThreadInformation) = FALSE;
                    if (ReturnLength)
                        *ReturnLength = 1;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return GetExceptionCode();
                }
                return STATUS_SUCCESS;
            }

            // -- ThreadBreakOnTermination: always report 0 --
            if (ThreadInformationClass == ThreadBreakOnTermination) {
                if (ThreadInformationLength != sizeof(ULONG))
                    return STATUS_INFO_LENGTH_MISMATCH;

                __try {
                    *static_cast<PULONG>(ThreadInformation) = 0;
                    if (ReturnLength)
                        *ReturnLength = sizeof(ULONG);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return GetExceptionCode();
                }
                return STATUS_SUCCESS;
            }

            // -- ThreadWow64Context: strip debug registers --
            if (ThreadInformationClass == ThreadWow64Context) {
                if (ThreadInformationLength != sizeof(WOW64_CONTEXT))
                    return STATUS_INFO_LENGTH_MISMATCH;

                __try {
                    auto* ctx =
                        static_cast<PWOW64_CONTEXT>(ThreadInformation);
                    ULONG original_flags = ctx->ContextFlags;
                    ctx->ContextFlags &= ~0x10u;

                    NTSTATUS status = original(
                        ThreadHandle, ThreadInformationClass,
                        ThreadInformation, ThreadInformationLength,
                        ReturnLength);

                    if (original_flags & 0x10) {
                        ctx->ContextFlags |= 0x10;
                        ctx->Dr0 = 0;
                        ctx->Dr1 = 0;
                        ctx->Dr2 = 0;
                        ctx->Dr3 = 0;
                        ctx->Dr6 = 0;
                        ctx->Dr7 = 0;
                    }

                    return status;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return GetExceptionCode();
                }
            }

            return original(ThreadHandle, ThreadInformationClass,
                            ThreadInformation, ThreadInformationLength,
                            ReturnLength);
        };
        ASSERT_TRUE(hook.enable(), HookFailed);
    }

    // ======================================================================
    // NtCreateThreadEx — strip debug-related creation flags
    // ======================================================================
    {
        auto res = mgr.hook_by_syscall_name("NtCreateThreadEx");
        ASSERT_TRUE(res, NotFound);
        static auto& hook = res.value();
        hook << [](PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                   POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                   PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
                   SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
                   PVOID AttributeList) -> NTSTATUS {
            auto original = hook.get_original<NtCreateThreadEx>();

            if (process_manager::current_is_target_ex() &&
                (CreateFlags & (THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER |
                                THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE))) {
                CreateFlags &= ~(THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER |
                                 THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE);
            }

            return original(ThreadHandle, DesiredAccess, ObjectAttributes,
                            ProcessHandle,
                            reinterpret_cast<PUSER_THREAD_START_ROUTINE>(StartRoutine),
                            Argument, CreateFlags,
                            ZeroBits, StackSize, MaximumStackSize,
                            static_cast<PPS_ATTRIBUTE_LIST>(AttributeList));
        };
        ASSERT_TRUE(hook.enable(), HookFailed);
    }

    // ======================================================================
    // NtCreateFile — hide driver file objects
    // ======================================================================
    {
        auto res = mgr.hook_by_syscall_name("NtCreateFile");
        ASSERT_TRUE(res, NotFound);
        static auto& hook = res.value();
        hook << [](PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                   POBJECT_ATTRIBUTES ObjectAttributes,
                   PIO_STATUS_BLOCK IoStatusBlock,
                   PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                   ULONG ShareAccess, ULONG CreateDisposition,
                   ULONG CreateOptions, PVOID EaBuffer,
                   ULONG EaLength) -> NTSTATUS {
            auto original = hook.get_original<NtCreateFile>();

            if (!process_manager::current_is_target_ex() ||
                ExGetPreviousMode() != UserMode) {
                return original(FileHandle, DesiredAccess, ObjectAttributes,
                                IoStatusBlock, AllocationSize, FileAttributes,
                                ShareAccess, CreateDisposition, CreateOptions,
                                EaBuffer, EaLength);
            }

            NTSTATUS status = original(
                FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
                CreateOptions, EaBuffer, EaLength);

            if (NT_SUCCESS(status)) {
                __try {
                    if (ObjectAttributes && ObjectAttributes->ObjectName &&
                        ObjectAttributes->ObjectName->Buffer) {
                        for (auto& drv :
                             process_manager::names::hidden_drivers) {
                            ANSI_STRING ansi_drv;
                            RtlInitAnsiString(&ansi_drv, drv);
                            UNICODE_STRING uni_drv{};
                            if (NT_SUCCESS(RtlAnsiStringToUnicodeString(
                                    &uni_drv, &ansi_drv, TRUE))) {
                                if (wcsstr(
                                        ObjectAttributes->ObjectName->Buffer,
                                        uni_drv.Buffer)) {
                                    RtlFreeUnicodeString(&uni_drv);
                                    ObCloseHandle(*FileHandle, UserMode);
                                    *FileHandle = INVALID_HANDLE_VALUE;
                                    return STATUS_OBJECT_NAME_NOT_FOUND;
                                }
                                RtlFreeUnicodeString(&uni_drv);
                            }
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    // swallow
                }
            }

            return status;
        };
        ASSERT_TRUE(hook.enable(), HookFailed);
    }

    // ======================================================================
    // NtGetNextProcess — skip hidden processes
    // ======================================================================
    {
        auto res = mgr.hook_by_syscall_name("NtGetNextProcess");
        ASSERT_TRUE(res, NotFound);
        static auto& hook = res.value();
        hook << [](HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                   ULONG HandleAttributes, ULONG Flags,
                   PHANDLE NewProcessHandle) -> NTSTATUS {
            auto original = hook.get_original<NtGetNextProcess>();

            NTSTATUS status = original(ProcessHandle, DesiredAccess,
                                       HandleAttributes, Flags,
                                       NewProcessHandle);

            if (!process_manager::current_is_target_ex() ||
                ExGetPreviousMode() != UserMode || !NT_SUCCESS(status)) {
                return status;
            }

            // If the returned process is hidden, skip to the next one
            PEPROCESS new_process = nullptr;
            NTSTATUS ob_status = ObReferenceObjectByHandle(
                *NewProcessHandle, 0, *PsProcessType, KernelMode,
                reinterpret_cast<PVOID*>(&new_process), nullptr);

            if (NT_SUCCESS(ob_status)) {
                if (process_manager::is_hidden(new_process)) {
                    HANDLE old_handle = *NewProcessHandle;
                    // Recurse to skip hidden process
                    status = hook.get_original<NtGetNextProcess>()(
                        *NewProcessHandle, DesiredAccess, HandleAttributes,
                        Flags, NewProcessHandle);
                    ObCloseHandle(old_handle, UserMode);
                }
                ObDereferenceObject(new_process);
            }

            return status;
        };
        ASSERT_TRUE(hook.enable(), HookFailed);
    }

    // ======================================================================
    // NtOpenProcess — block opening hidden processes
    // ======================================================================
    {
        auto res = mgr.hook_by_syscall_name("NtOpenProcess");
        ASSERT_TRUE(res, NotFound);
        static auto& hook = res.value();
        hook << [](PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                   POBJECT_ATTRIBUTES ObjectAttributes,
                   PCLIENT_ID ClientId) -> NTSTATUS {
            auto original = hook.get_original<NtOpenProcess>();

            if (!process_manager::current_is_target_ex() ||
                ExGetPreviousMode() != UserMode) {
                return original(ProcessHandle, DesiredAccess, ObjectAttributes,
                                ClientId);
            }

            if (ClientId) {
                __try {
                    if (ClientId->UniqueProcess &&
                        process_manager::is_hidden(ClientId->UniqueProcess)) {
                        // Replace PID with an invalid one so the call fails
                        HANDLE original_pid = ClientId->UniqueProcess;
                        ClientId->UniqueProcess =
                            UlongToHandle(0xFFFFFFFCu);
                        NTSTATUS status =
                            original(ProcessHandle, DesiredAccess,
                                     ObjectAttributes, ClientId);
                        ClientId->UniqueProcess = original_pid;
                        return status;
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return GetExceptionCode();
                }
            }

            return original(ProcessHandle, DesiredAccess, ObjectAttributes,
                            ClientId);
        };
        ASSERT_TRUE(hook.enable(), HookFailed);
    }

    // ======================================================================
    // NtOpenThread — block opening hidden process threads
    // ======================================================================
    {
        auto res = mgr.hook_by_syscall_name("NtOpenThread");
        ASSERT_TRUE(res, NotFound);
        static auto& hook = res.value();
        hook << [](PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                   POBJECT_ATTRIBUTES ObjectAttributes,
                   PCLIENT_ID ClientId) -> NTSTATUS {
            auto original = hook.get_original<NtOpenThread>();

            if (!process_manager::current_is_target_ex() ||
                ExGetPreviousMode() != UserMode) {
                return original(ThreadHandle, DesiredAccess, ObjectAttributes,
                                ClientId);
            }

            if (ClientId && ClientId->UniqueThread) {
                __try {
                    PETHREAD target_thread = nullptr;
                    if (NT_SUCCESS(PsLookupThreadByThreadId(
                            ClientId->UniqueThread, &target_thread))) {
                        PEPROCESS owner = IoThreadToProcess(target_thread);
                        ObDereferenceObject(target_thread);

                        if (process_manager::is_hidden(owner)) {
                            HANDLE original_tid = ClientId->UniqueThread;
                            ClientId->UniqueThread =
                                UlongToHandle(0xFFFFFFFCu);
                            NTSTATUS status =
                                original(ThreadHandle, DesiredAccess,
                                         ObjectAttributes, ClientId);
                            ClientId->UniqueThread = original_tid;
                            return status;
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return GetExceptionCode();
                }
            }

            return original(ThreadHandle, DesiredAccess, ObjectAttributes,
                            ClientId);
        };
        ASSERT_TRUE(hook.enable(), HookFailed);
    }

    // ======================================================================
    // NtYieldExecution — always return STATUS_SUCCESS for targets
    // ======================================================================
    {
        auto res = mgr.hook_by_syscall_name("NtYieldExecution");
        ASSERT_TRUE(res, NotFound);
        static auto& hook = res.value();
        hook << []() -> NTSTATUS {
            auto original = hook.get_original<NtYieldExecution>();
            original();

            if (process_manager::current_is_target_ex())
                return STATUS_SUCCESS;

            return original();
        };
        ASSERT_TRUE(hook.enable(), HookFailed);
    }

    // ======================================================================
    // NtQueryInformationJobObject — strip hidden PIDs
    // ======================================================================
    {
        auto res = mgr.hook_by_syscall_name("NtQueryInformationJobObject");
        ASSERT_TRUE(res, NotFound);
        static auto& hook = res.value();
        hook << [](HANDLE JobHandle, JOBOBJECTINFOCLASS JobInformationClass,
                   PVOID JobInformation, ULONG JobInformationLength,
                   PULONG ReturnLength) -> NTSTATUS {
            auto original = hook.get_original<NtQueryInformationJobObject>();
            NTSTATUS status = original(JobHandle, JobInformationClass,
                                       JobInformation, JobInformationLength,
                                       ReturnLength);

            if (!process_manager::current_is_target_ex() ||
                !NT_SUCCESS(status) ||
                JobInformationClass != JobObjectBasicProcessIdList) {
                return status;
            }

            auto* list = static_cast<PJOBOBJECT_BASIC_PROCESS_ID_LIST_LOCAL>(
                JobInformation);

            ULONG write_idx = 0;
            for (ULONG i = 0; i < list->NumberOfProcessIdsInList; ++i) {
                auto ep = pid_to_eprocess(
                    reinterpret_cast<HANDLE>(list->ProcessIdList[i]));
                if (ep && process_manager::is_hidden(ep))
                    continue;
                list->ProcessIdList[write_idx++] = list->ProcessIdList[i];
            }

            if (write_idx < list->NumberOfProcessIdsInList) {
                list->NumberOfAssignedProcesses = write_idx;
                list->NumberOfProcessIdsInList = write_idx;
            }

            return status;
        };
        ASSERT_TRUE(hook.enable(), HookFailed);
    }

    // ======================================================================
    // NtContinue — strip debug registers from context
    // ======================================================================
    {
        auto res = mgr.hook_by_syscall_name("NtContinue");
        ASSERT_TRUE(res, NotFound);
        static auto& hook = res.value();
        hook << [](PCONTEXT Context, BOOLEAN TestAlert) -> NTSTATUS {
            auto original = hook.get_original<NtContinue>();

            if (!process_manager::current_is_target_ex() ||
                ExGetPreviousMode() != UserMode) {
                return original(Context, TestAlert);
            }

            __try {
                Context->ContextFlags &= ~0x10u;  // CONTEXT_DEBUG_REGISTERS
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                return GetExceptionCode();
            }

            return original(Context, TestAlert);
        };
        ASSERT_TRUE(hook.enable(), HookFailed);
    }

    log("debugger_hide: all hooks registered successfully");
    return core::ok();
}

}  // namespace debugger_hide

