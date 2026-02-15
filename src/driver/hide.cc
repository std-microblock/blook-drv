#include "hide.hpp"

#include <winscard.h>
#include <ntifs.h>

#include "core/core.hpp"
#include "core/expected.hpp"
#include "ntddscsi.h"
#include "ssdt/ssdt_hook.hpp"

extern "C" {
// PsIsProtectedProcess
NTSYSAPI BOOLEAN NTAPI PsIsProtectedProcess(PEPROCESS Process);
}

// Minimal kernel-internal structures used for enumerating and patching
// object manager callback lists. These are intentionally limited to the
// fields we need here and placed at file scope to avoid leaking them
// into headers.

typedef struct _OBJECT_TYPE {
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;
    VOID* DefaultObject;
    UCHAR Index;
    unsigned __int32 TotalNumberOfObjects;
    unsigned __int32 TotalNumberOfHandles;
    unsigned __int32 HighWaterNumberOfObjects;
    unsigned __int32 HighWaterNumberOfHandles;
    char TypeInfo[0x78];
    EX_PUSH_LOCK TypeLock;
    unsigned __int32 Key;
    LIST_ENTRY CallbackList;
} OBJECT_TYPE, *POBJECT_TYPE;

typedef struct _CALLBACK_ENTRY_ITEM {
    LIST_ENTRY EntryItemList;
    OB_OPERATION Operations;
    struct _CALLBACK_ENTRY* CallbackEntry;
    POBJECT_TYPE ObjectType;
    POB_PRE_OPERATION_CALLBACK PreOperation;
    POB_POST_OPERATION_CALLBACK PostOperation;
    __int64 unk;
} CALLBACK_ENTRY_ITEM, *PCALLBACK_ENTRY_ITEM;

namespace hide {

namespace globals {
const wchar_t* wsProtectedProcesses[] = {
    L"cheatengine-x86_64.exe",
    L"cheatengine-x86_64-SSE4-AVX2.exe",
    L"x64dbg.exe",
    L"windbg.exe",
    L"SystemInformer.exe",
};
const wchar_t* wsMonitoredProcesses[] = {L"Taskmgr.exe"};
const wchar_t* wsBlacklistedProcessess[] = {L"test_app.exe"};
const char* szProtectedDrivers[] = {"blook-drv.sys"};
}  // namespace globals

namespace tools {

bool GetProcessName(HANDLE PID, PUNICODE_STRING out_name) {
    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(PID, &process);
    if (!NT_SUCCESS(status))
        return false;

    bool result = GetProcessNameByPEPROCESS(process, out_name);
    ObDereferenceObject(process);
    return result;
}

bool GetProcessNameByPEPROCESS(PEPROCESS process, PUNICODE_STRING out_name) {
    PUNICODE_STRING name = nullptr;
    // SeLocateProcessImageName is available on Vista+
    NTSTATUS status = SeLocateProcessImageName(process, &name);
    if (!NT_SUCCESS(status))
        return false;

    out_name->Length = name->Length;
    out_name->MaximumLength = name->MaximumLength;
    out_name->Buffer =
        (PWCH)ExAllocatePoolWithTag(NonPagedPool, name->MaximumLength, 'hide');

    if (out_name->Buffer) {
        RtlCopyUnicodeString(out_name, name);
        ExFreePool(name);
        return true;
    }

    ExFreePool(name);
    return false;
}

void FreeUnicodeString(PUNICODE_STRING str) {
    if (str && str->Buffer) {
        ExFreePool(str->Buffer);
        str->Buffer = nullptr;
        str->Length = str->MaximumLength = 0;
    }
}

void DumpMZ(PUCHAR base) {
    // Just a stub for now as in the snippet
    UNREFERENCED_PARAMETER(base);
}

void SwapEndianness(char* str, size_t size) {
    for (size_t i = 0; i < size; i += 2) {
        char tmp = str[i];
        str[i] = str[i + 1];
        str[i + 1] = tmp;
    }
}

bool IsProtectedProcess(HANDLE PID) {
    UNICODE_STRING wsProcName{};
    if (!GetProcessName(PID, &wsProcName))
        return false;

    bool bResult = false;
    if (wsProcName.Buffer) {
        for (int i = 0; i < (int)(sizeof(globals::wsProtectedProcesses) /
                                  sizeof(globals::wsProtectedProcesses[0]));
             ++i) {
            if (wcsstr(wsProcName.Buffer, globals::wsProtectedProcesses[i])) {
                bResult = true;
                break;
            }
        }
        FreeUnicodeString(&wsProcName);
    }
    return bResult;
}

bool IsProtectedProcess(ULONG_PTR PID) {
    return IsProtectedProcess((HANDLE)PID);
}

bool IsProtectedProcess(PWCH Buffer) {
    if (!Buffer)
        return false;
    for (int i = 0; i < (int)(sizeof(globals::wsProtectedProcesses) /
                              sizeof(globals::wsProtectedProcesses[0]));
         ++i) {
        if (wcsstr(Buffer, globals::wsProtectedProcesses[i])) {
            return true;
        }
    }
    return false;
}

bool IsProtectedProcessEx(PEPROCESS Process) {
    UNICODE_STRING wsProcName{};
    if (!GetProcessNameByPEPROCESS(Process, &wsProcName))
        return false;

    bool bResult = false;
    if (wsProcName.Buffer) {
        for (int i = 0; i < (int)(sizeof(globals::wsProtectedProcesses) /
                                  sizeof(globals::wsProtectedProcesses[0]));
             ++i) {
            if (wcsstr(wsProcName.Buffer, globals::wsProtectedProcesses[i])) {
                bResult = true;
                break;
            }
        }
        FreeUnicodeString(&wsProcName);
    }
    return bResult;
}

bool IsMonitoredProcess(HANDLE PID) {
    UNICODE_STRING wsProcName{};
    if (!GetProcessName(PID, &wsProcName))
        return false;

    bool bResult = false;
    if (wsProcName.Buffer) {
        for (int i = 0; i < (int)(sizeof(globals::wsMonitoredProcesses) /
                                  sizeof(globals::wsMonitoredProcesses[0]));
             ++i) {
            if (wcsstr(wsProcName.Buffer, globals::wsMonitoredProcesses[i])) {
                bResult = true;
                break;
            }
        }
        FreeUnicodeString(&wsProcName);
    }
    return bResult;
}

bool IsMonitoredProcessEx(PEPROCESS Process) {
    UNICODE_STRING wsProcName{};
    if (!GetProcessNameByPEPROCESS(Process, &wsProcName))
        return false;

    bool bResult = false;
    if (wsProcName.Buffer) {
        for (int i = 0; i < (int)(sizeof(globals::wsMonitoredProcesses) /
                                  sizeof(globals::wsMonitoredProcesses[0]));
             ++i) {
            if (wcsstr(wsProcName.Buffer, globals::wsMonitoredProcesses[i])) {
                bResult = true;
                break;
            }
        }
        FreeUnicodeString(&wsProcName);
    }
    return bResult;
}

bool IsBlacklistedProcess(HANDLE PID) {
    UNICODE_STRING wsProcName{};
    if (!GetProcessName(PID, &wsProcName))
        return false;

    bool bResult = false;
    if (wsProcName.Buffer) {
        for (int i = 0; i < (int)(sizeof(globals::wsBlacklistedProcessess) /
                                  sizeof(globals::wsBlacklistedProcessess[0]));
             ++i) {
            if (wcsstr(wsProcName.Buffer,
                       globals::wsBlacklistedProcessess[i])) {
                bResult = true;
                break;
            }
        }
        FreeUnicodeString(&wsProcName);
    }
    return bResult;
}

bool IsBlacklistedProcessEx(PEPROCESS Process) {
    UNICODE_STRING wsProcName{};
    if (!GetProcessNameByPEPROCESS(Process, &wsProcName))
        return false;

    bool bResult = false;
    if (wsProcName.Buffer) {
        for (int i = 0; i < (int)(sizeof(globals::wsBlacklistedProcessess) /
                                  sizeof(globals::wsBlacklistedProcessess[0]));
             ++i) {
            if (wcsstr(wsProcName.Buffer,
                       globals::wsBlacklistedProcessess[i])) {
                bResult = true;
                break;
            }
        }
        FreeUnicodeString(&wsProcName);
    }
    return bResult;
}

// --- OB callback patching helpers ------------------------------------------------

struct ObCallbackBackup {
    PCALLBACK_ENTRY_ITEM Entry;
    POB_PRE_OPERATION_CALLBACK OldPre;
    POB_POST_OPERATION_CALLBACK OldPost;
};

static OB_PREOP_CALLBACK_STATUS ObPreOpStub(PVOID RegistrationContext,
                                            POB_PRE_OPERATION_INFORMATION OpInfo) {
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(OpInfo);
    return (OB_PREOP_CALLBACK_STATUS)0; /* continue */
}

static void ObPostOpStub(PVOID RegistrationContext,
                         POB_POST_OPERATION_INFORMATION OpInfo) {
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(OpInfo);
}

// Patch every callback entry in `objType->CallbackList` to point at the provided
// stubs. Returns an allocated array of ObCallbackBackup (must be freed by the
// caller with ExFreePool) and sets outCount. Returns nullptr on failure.
static ObCallbackBackup* PatchObjectTypeCallbacks(POBJECT_TYPE objType,
                                                  POB_PRE_OPERATION_CALLBACK stubPre,
                                                  POB_POST_OPERATION_CALLBACK stubPost,
                                                  SIZE_T* outCount) {
    if (!objType || !outCount)
        return nullptr;

    PLIST_ENTRY pHead = &objType->CallbackList;
    PLIST_ENTRY pEntry = pHead->Flink;
    SIZE_T count = 0;

    // first pass: count entries
    while (pEntry != pHead) {
        ++count;
        pEntry = pEntry->Flink;
    }

    if (count == 0) {
        *outCount = 0;
        return nullptr;
    }

    ObCallbackBackup* backups = (ObCallbackBackup*)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(ObCallbackBackup) * count, 'cbkH');
    if (!backups) {
        *outCount = 0;
        return nullptr;
    }

    RtlZeroMemory(backups, sizeof(ObCallbackBackup) * count);

    // second pass: replace and save
    SIZE_T idx = 0;
    pEntry = pHead->Flink;
    while (pEntry != pHead && idx < count) {
        PCALLBACK_ENTRY_ITEM cItem =
            CONTAINING_RECORD(pEntry, CALLBACK_ENTRY_ITEM, EntryItemList);

        backups[idx].Entry = cItem;
        backups[idx].OldPre = cItem->PreOperation;
        backups[idx].OldPost = cItem->PostOperation;

        // replace with stubs
        cItem->PreOperation = stubPre;
        cItem->PostOperation = stubPost;

        ++idx;
        pEntry = pEntry->Flink;
    }

    *outCount = idx;
    return backups;
}

static void RestoreObjectTypeCallbacks(ObCallbackBackup* backups, SIZE_T count) {
    if (!backups || count == 0)
        return;

    for (SIZE_T i = 0; i < count; ++i) {
        PCALLBACK_ENTRY_ITEM entry = backups[i].Entry;
        if (!entry)
            continue;
        entry->PreOperation = backups[i].OldPre;
        entry->PostOperation = backups[i].OldPost;
    }
}

// --------------------------------------------------------------------------------
}  // namespace tools

// Hooks implementation using SsdtHookManager

core::VoidResult register_hooks() {
    auto& manager = ssdt::SsdtHookManager::instance();

    // NtOpenProcess
    auto result_open = manager.hook_by_syscall_name("NtOpenProcess");
    ASSERT_TRUE(result_open, NotFound);
    static auto& open_hook = result_open.value();
    open_hook << [](PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                    POBJECT_ATTRIBUTES ObjectAttributes,
                    PCLIENT_ID ClientId) -> NTSTATUS {
        auto original = open_hook.get_original<NtOpenProcess>();

        if (tools::IsProtectedProcess(PsGetCurrentProcessId())) {
            // For protected callers: temporarily replace all OB callbacks
            // (both Process and Thread object types) with no-op stubs, call
            // the original NtOpenProcess, then restore the callbacks.
            SIZE_T procCount = 0, threadCount = 0;
            auto* procBackups = (tools::ObCallbackBackup*)nullptr;
            auto* threadBackups = (tools::ObCallbackBackup*)nullptr;

            POBJECT_TYPE pProcType = *PsProcessType;
            POBJECT_TYPE pThreadType = *PsThreadType;

            if (pProcType)
                procBackups = tools::PatchObjectTypeCallbacks(pProcType,
                                                             tools::ObPreOpStub,
                                                             tools::ObPostOpStub,
                                                             &procCount);
            if (pThreadType)
                threadBackups = tools::PatchObjectTypeCallbacks(pThreadType,
                                                                tools::ObPreOpStub,
                                                                tools::ObPostOpStub,
                                                                &threadCount);

            NTSTATUS status = original(ProcessHandle, DesiredAccess,
                                       ObjectAttributes, ClientId);

            if (procBackups) {
                tools::RestoreObjectTypeCallbacks(procBackups, procCount);
                ExFreePool(procBackups);
            }
            if (threadBackups) {
                tools::RestoreObjectTypeCallbacks(threadBackups, threadCount);
                ExFreePool(threadBackups);
            }

            return status;
        } else {
            NTSTATUS status = original(ProcessHandle, DesiredAccess,
                                       ObjectAttributes, ClientId);

            if (NT_SUCCESS(status) && ClientId) {
                if (tools::IsBlacklistedProcess(PsGetCurrentProcessId())) {
                    if (tools::IsProtectedProcess(ClientId->UniqueProcess)) {
                        ZwClose(*ProcessHandle);
                        *ProcessHandle = (HANDLE)-1;
                        return STATUS_ACCESS_DENIED;
                    }
                }
            }
            return status;
        }
    };
    ASSERT_TRUE(open_hook.enable(), HookFailed);

    // NtQuerySystemInformation
    auto result_query =
        manager.hook_by_syscall_name("NtQuerySystemInformation");
    ASSERT_TRUE(result_query, NotFound);
    static auto& query_hook = result_query.value();
    query_hook << [](SYSTEM_INFORMATION_CLASS SystemInformationClass,
                     PVOID Buffer, ULONG Length,
                     PULONG ReturnLength) -> NTSTATUS {
        auto original = query_hook.get_original<NtQuerySystemInformation>();
        NTSTATUS status =
            original(SystemInformationClass, Buffer, Length, ReturnLength);

        if (tools::IsProtectedProcess(PsGetCurrentProcessId()))
            return status;

        if (NT_SUCCESS(status) && Buffer) {
            if (SystemInformationClass ==
                (SYSTEM_INFORMATION_CLASS)11 /* SystemModuleInformation */) {
                auto pModule = (PRTL_PROCESS_MODULES)Buffer;
                for (ULONG i = 0; i < pModule->NumberOfModules; ++i) {
                    for (int x = 0;
                         x < (int)(sizeof(globals::szProtectedDrivers) /
                                   sizeof(globals::szProtectedDrivers[0]));
                         ++x) {
                        if (strstr((char*)pModule->Modules[i].FullPathName,
                                   globals::szProtectedDrivers[x])) {
                            if (i + 1 < pModule->NumberOfModules)
                                RtlMoveMemory(
                                    &pModule->Modules[i],
                                    &pModule->Modules[i + 1],
                                    (pModule->NumberOfModules - i - 1) *
                                        sizeof(RTL_PROCESS_MODULE_INFORMATION));

                            pModule->NumberOfModules--;
                            i--;
                            break;
                        }
                    }
                }
            } else if (
                SystemInformationClass ==
                (SYSTEM_INFORMATION_CLASS)5 /* SystemProcessInformation */) {
                auto pCurr = (SYSTEM_PROCESS_INFORMATION*)Buffer;
                SYSTEM_PROCESS_INFORMATION* pPrev = nullptr;
                while (pCurr) {
                    if (pCurr->ImageName.Buffer &&
                        tools::IsProtectedProcess(pCurr->ImageName.Buffer)) {
                        if (pPrev) {
                            if (pCurr->NextEntryOffset)
                                pPrev->NextEntryOffset +=
                                    pCurr->NextEntryOffset;
                            else
                                pPrev->NextEntryOffset = 0;
                        } else {
                            // Can't easily hide the first process in the
                            // list this way without copying
                        }
                    } else {
                        pPrev = pCurr;
                    }
                    if (!pCurr->NextEntryOffset)
                        break;
                    pCurr =
                        (SYSTEM_PROCESS_INFORMATION*)((PUCHAR)pCurr +
                                                      pCurr->NextEntryOffset);
                }
            }
        }
        return status;
    };
    ASSERT_TRUE(query_hook.enable(), HookFailed);

    // NtWriteVirtualMemory
    auto result_write = manager.hook_by_syscall_name("NtWriteVirtualMemory");
    ASSERT_TRUE(result_write, NotFound);
    static auto& write_hook = result_write.value();
    write_hook << [](HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
                     SIZE_T NumberOfBytesToWrite,
                     PSIZE_T NumberOfBytesWritten) -> NTSTATUS {
        auto original = write_hook.get_original<NtWriteVirtualMemory>();
        NTSTATUS res = original(ProcessHandle, BaseAddress, Buffer,
                                NumberOfBytesToWrite, NumberOfBytesWritten);

        if (tools::IsProtectedProcess(PsGetCurrentProcessId()) ||
            PsIsSystemProcess(PsGetCurrentProcess()))
            return res;

        if (NT_SUCCESS(res)) {
            PEPROCESS Process = nullptr;
            NTSTATUS ret = ObReferenceObjectByHandle(
                ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(),
                (PVOID*)&Process, nullptr);
            if (!NT_SUCCESS(ret))
                return res;

            if (tools::IsMonitoredProcessEx(Process)) {
                UNICODE_STRING wsProcName{};
                if (tools::GetProcessName(PsGetCurrentProcessId(),
                                          &wsProcName)) {
                    if (wsProcName.Buffer) {
                        auto ShortName = wcsrchr(wsProcName.Buffer, L'\\');
                        log("[ WPM ] From: %p to %ws with BaseAddress 0x%p "
                            "Buffer 0x%p Length %llu",
                            PsGetCurrentProcessId(), ShortName, BaseAddress,
                            Buffer, (unsigned long long)NumberOfBytesToWrite);
                        tools::FreeUnicodeString(&wsProcName);
                    }
                }
            }

            ObDereferenceObject(Process);
        }
        return res;
    };
    ASSERT_TRUE(write_hook.enable(), HookFailed);

    // NtAllocateVirtualMemory
    auto result_alloc = manager.hook_by_syscall_name("NtAllocateVirtualMemory");
    ASSERT_TRUE(result_alloc, NotFound);
    static auto& alloc_hook = result_alloc.value();
    alloc_hook << [](HANDLE ProcessHandle, PVOID* BaseAddress,
                     ULONG_PTR ZeroBits, PSIZE_T RegionSize,
                     ULONG AllocationType, ULONG Protect) -> NTSTATUS {
        auto original = alloc_hook.get_original<NtAllocateVirtualMemory>();
        NTSTATUS res = original(ProcessHandle, BaseAddress, ZeroBits,
                                RegionSize, AllocationType, Protect);

        if (PsIsProtectedProcess(PsGetCurrentProcess()) ||
            PsIsSystemProcess(PsGetCurrentProcess()) ||
            tools::IsProtectedProcess(PsGetCurrentProcessId()))
            return res;

        if (NT_SUCCESS(res) && BaseAddress && RegionSize &&
            *RegionSize >= 0x1000) {
            PEPROCESS Process = nullptr;
            NTSTATUS ret = ObReferenceObjectByHandle(
                ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(),
                (PVOID*)&Process, nullptr);
            if (!NT_SUCCESS(ret))
                return res;

            if (tools::IsMonitoredProcessEx(Process)) {
                UNICODE_STRING wsProcName{};
                if (tools::GetProcessName(PsGetCurrentProcessId(),
                                          &wsProcName)) {
                    if (wsProcName.Buffer) {
                        auto ShortName = wcsrchr(wsProcName.Buffer, L'\\');
                        log("[ AVM ] From: %p to %ws with BaseAddress 0x%p "
                            "Length 0x%llx Type 0x%X Protect 0x%X",
                            PsGetCurrentProcessId(), ShortName, *BaseAddress,
                            *RegionSize, AllocationType, Protect);
                        tools::FreeUnicodeString(&wsProcName);
                    }
                }
            }

            ObDereferenceObject(Process);
        }
        return res;
    };
    ASSERT_TRUE(alloc_hook.enable(), HookFailed);

    // NtFreeVirtualMemory
    auto result_free = manager.hook_by_syscall_name("NtFreeVirtualMemory");
    ASSERT_TRUE(result_free, NotFound);
    static auto& free_hook = result_free.value();
    free_hook << [](HANDLE ProcessHandle, PVOID* BaseAddress,
                    PSIZE_T RegionSize, ULONG FreeType) -> NTSTATUS {
        auto original = free_hook.get_original<NtFreeVirtualMemory>();
        NTSTATUS res =
            original(ProcessHandle, BaseAddress, RegionSize, FreeType);

        if (PsIsProtectedProcess(PsGetCurrentProcess()) ||
            PsIsSystemProcess(PsGetCurrentProcess()) ||
            tools::IsProtectedProcess(PsGetCurrentProcessId()))
            return res;

        if (NT_SUCCESS(res) && BaseAddress && RegionSize &&
            *RegionSize >= 0x1000) {
            PEPROCESS Process = nullptr;
            NTSTATUS ret = ObReferenceObjectByHandle(
                ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(),
                (PVOID*)&Process, nullptr);
            if (!NT_SUCCESS(ret))
                return res;

            if (tools::IsMonitoredProcessEx(Process)) {
                UNICODE_STRING wsProcName{};
                if (tools::GetProcessName(PsGetCurrentProcessId(),
                                          &wsProcName)) {
                    if (wsProcName.Buffer) {
                        auto ShortName = wcsrchr(wsProcName.Buffer, L'\\');
                        log("[ FVM ] From: %p to %ws with BaseAddress 0x%p "
                            "Length 0x%llx FreeType 0x%X",
                            PsGetCurrentProcessId(), ShortName, *BaseAddress,
                            *RegionSize, FreeType);
                        tools::DumpMZ((PUCHAR)*BaseAddress);
                        tools::FreeUnicodeString(&wsProcName);
                    }
                }
            }

            ObDereferenceObject(Process);
        }
        return res;
    };
    ASSERT_TRUE(free_hook.enable(), HookFailed);

    // NtLoadDriver - allow filtering if needed
    auto result_load = manager.hook_by_syscall_name("NtLoadDriver");
    ASSERT_TRUE(result_load, NotFound);
    static auto& load_hook = result_load.value();
    load_hook << [](PUNICODE_STRING DriverServiceName) -> NTSTATUS {
        bool bLoad = true;
        if (DriverServiceName && DriverServiceName->Buffer) {
            // Example to block specific driver names (uncomment to use):
            // if (wcsstr(DriverServiceName->Buffer, L"BEDaisy.sys"))
            //     bLoad = false;
        }

        if (!bLoad)
            return STATUS_UNSUCCESSFUL;

        auto original = load_hook.get_original<NtLoadDriver>();
        NTSTATUS ret = original(DriverServiceName);
        if (NT_SUCCESS(ret))
            log("Loading Driver: %ws",
                DriverServiceName ? DriverServiceName->Buffer : L"(null)");
        return ret;
    };
    ASSERT_TRUE(load_hook.enable(), HookFailed);

    // Shadow-SSDT (win32k) hooks for window enumeration / foreground handling
    auto result_win_from_point = manager.hook_by_syscall_name(
        "NtUserWindowFromPoint", ssdt::HookType::ShadowSsdt);
    ASSERT_TRUE(result_win_from_point, NotFound);
    static auto& winfp_hook = result_win_from_point.value();
    winfp_hook << [](POINT p) -> HWND {
        auto original = winfp_hook.get_original<NtUserWindowFromPoint>();
        const auto res = original(p);
        if (PsIsProtectedProcess(PsGetCurrentProcess()) ||
            PsIsSystemProcess(PsGetCurrentProcess()))
            return res;
        if (!tools::IsBlacklistedProcessEx(PsGetCurrentProcess()))
            return res;
        return 0;
    };
    ASSERT_TRUE(winfp_hook.enable(), HookFailed);

    auto result_qwindow = manager.hook_by_syscall_name(
        "NtUserQueryWindow", ssdt::HookType::ShadowSsdt);
    ASSERT_TRUE(result_qwindow, HookFailed);

    static auto& qwin_hook = result_qwindow.value();
    qwin_hook <<
        [](HWND WindowHandle, WINDOWINFOCLASS TypeInformation) -> ULONG_PTR {
        auto original = qwin_hook.get_original<NtUserQueryWindow>();
        const auto res = original(WindowHandle, TypeInformation);
        if (PsIsProtectedProcess(PsGetCurrentProcess()) ||
            PsIsSystemProcess(PsGetCurrentProcess()))
            return res;
        if (!tools::IsBlacklistedProcessEx(PsGetCurrentProcess()))
            return res;
        auto PID = qwin_hook.get_original<NtUserQueryWindow>()(WindowHandle,
                                                               WindowProcess);
        if (tools::IsProtectedProcess((HANDLE)PID))
            return 0;
        return res;
    };
    ASSERT_TRUE(qwin_hook.enable(), HookFailed);

    auto result_findwnd = manager.hook_by_syscall_name(
        "NtUserFindWindowEx", ssdt::HookType::ShadowSsdt);
    ASSERT_TRUE(result_findwnd, HookFailed);
    static auto& find_hook = result_findwnd.value();
    find_hook << [](HWND hWndParent, HWND hWndChildAfter,
                    PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow,
                    DWORD dwType) -> HWND {
        auto original = find_hook.get_original<NtUserFindWindowEx>();
        const auto res =
            original(hWndParent, hWndChildAfter, lpszClass, lpszWindow, dwType);
        if (PsIsProtectedProcess(PsGetCurrentProcess()) ||
            PsIsSystemProcess(PsGetCurrentProcess()))
            return res;
        if (!tools::IsBlacklistedProcessEx(PsGetCurrentProcess()))
            return res;
        if (res) {
            auto PID =
                qwin_hook.get_original<NtUserQueryWindow>()(res, WindowProcess);
            if (tools::IsProtectedProcess(PID))
                return NULL;
        }
        return res;
    };
    ASSERT_TRUE(find_hook.enable(), HookFailed);

    auto result_build = manager.hook_by_syscall_name(
        "NtUserBuildHwndList", ssdt::HookType::ShadowSsdt);
    ASSERT_TRUE(result_build, HookFailed);
    static auto& build_hook = result_build.value();

    build_hook << [](HANDLE DesktopHandle, HWND StartWindowHandle,
                     LOGICAL IncludeChildren, LOGICAL ExcludeImmersive,
                     ULONG ThreadId, ULONG HwndListInformationLength,
                     HWND* HwndListInformation,
                     PULONG ReturnLength) -> NTSTATUS {
        auto original = build_hook.get_original<NtUserBuildHwndList>();
        const auto res =
            original(DesktopHandle, StartWindowHandle, IncludeChildren,
                     ExcludeImmersive, ThreadId, HwndListInformationLength,
                     HwndListInformation, ReturnLength);

        if (PsIsProtectedProcess(PsGetCurrentProcess()) ||
            PsIsSystemProcess(PsGetCurrentProcess()))
            return res;
        if (!tools::IsBlacklistedProcessEx(PsGetCurrentProcess()))
            return res;

        if (IncludeChildren == 1) {
            auto PID = qwin_hook.get_original<NtUserQueryWindow>()(
                StartWindowHandle, WindowProcess);
            if (tools::IsProtectedProcess(PID))
                return STATUS_UNSUCCESSFUL;
        }

        if (NT_SUCCESS(res)) {
            ULONG i = 0;
            ULONG j;

            while (i < *ReturnLength) {
                auto PID = qwin_hook.get_original<NtUserQueryWindow>()(
                    HwndListInformation[i], WindowProcess);
                if (tools::IsProtectedProcess(PID)) {
                    for (j = i; j < (*ReturnLength) - 1; j++)
                        HwndListInformation[j] = HwndListInformation[j + 1];
                    HwndListInformation[*ReturnLength - 1] = 0;
                    (*ReturnLength)--;
                    continue;
                }
                i++;
            }
        }
        return res;
    };
    ASSERT_TRUE(build_hook.enable(), HookFailed);

    // NtUserGetForegroundWindow
    auto result_fg = manager.hook_by_syscall_name("NtUserGetForegroundWindow",
                                                  ssdt::HookType::ShadowSsdt);
    ASSERT_TRUE(result_fg, HookFailed);
    static auto& fg_hook = result_fg.value();
    static HWND LastForeWnd = HWND(-1);
    fg_hook << [](VOID) -> HWND {
        auto original = fg_hook.get_original<NtUserGetForegroundWindow>();
        const auto res = original();
        if (PsIsProtectedProcess(PsGetCurrentProcess()) ||
            PsIsSystemProcess(PsGetCurrentProcess()))
            return res;
        if (!tools::IsBlacklistedProcessEx(PsGetCurrentProcess()))
            return res;
        auto PID =
            qwin_hook.get_original<NtUserQueryWindow>()(res, WindowProcess);
        if (tools::IsProtectedProcess(PID))
            return LastForeWnd;
        else
            LastForeWnd = res;

        return res;
    };
    ASSERT_TRUE(fg_hook.enable(), HookFailed);

    return core::ok();
}

}  // namespace hide
