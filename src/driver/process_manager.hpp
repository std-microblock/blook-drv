#pragma once

#include <ntifs.h>
#include <windef.h>

#include "Veil.h"

namespace process_manager {

// Maximum number of each process category we track
constexpr size_t kMaxTargetProcesses = 16;
constexpr size_t kMaxHiddenProcesses = 16;
constexpr size_t kMaxMonitoredProcesses = 16;

// Process categories:
//   target_process  : the process being protected from anti-debug detection
//                     (e.g. a game). All debugger-hiding hooks apply when
//                     the current caller is a target process.
//   hidden_process  : the debugger / tool process that should be hidden
//                     from enumeration (e.g. x64dbg, cheatengine).
//                     These are stripped from NtQuerySystemInformation,
//                     handle lists, window lists, etc.
//   monitor_process : processes we log activity on (e.g. Taskmgr).
//                     Write / alloc / free calls targeting them are logged.

// Process name lists (matched via wcsstr against the full image path)
namespace names {

inline const wchar_t* target[] = {
    L"test_app.exe",    L"al-khaser_x64.exe", L"Arknights.exe",
    L"helldivers2.exe", L"GameMon.des",       L"GameMon64.des",
};

inline const wchar_t* hidden[] = {
    L"cheatengine-x86_64.exe",
    L"cheatengine-x86_64-SSE4-AVX2.exe",
    L"x64dbg.exe",
    L"windbg.exe",
    L"SystemInformer.exe",
};

inline const wchar_t* monitored[] = {
    L"Taskmgr.exe",
};

inline const char* hidden_drivers[] = {
    "blook-drv.sys",
};

}  // namespace names

// --------------------------------------------------------------------------
// Process name resolution helpers
// --------------------------------------------------------------------------

// Resolve a process image name from PID. Caller must call free_name() after.
bool get_name_by_pid(HANDLE pid, PUNICODE_STRING out);

// Resolve a process image name from PEPROCESS. Caller must call free_name().
bool get_name_by_eprocess(PEPROCESS process, PUNICODE_STRING out);

// Free a UNICODE_STRING buffer allocated by get_name_*.
void free_name(PUNICODE_STRING str);

// --------------------------------------------------------------------------
// Classification queries — by PID
// --------------------------------------------------------------------------
bool is_target(HANDLE pid);
bool is_hidden(HANDLE pid);
bool is_monitored(HANDLE pid);

// Overloads for ULONG_PTR (e.g. from NtUserQueryWindow return values)
inline bool is_target(ULONG_PTR pid) {
    return is_target(reinterpret_cast<HANDLE>(pid));
}
inline bool is_hidden(ULONG_PTR pid) {
    return is_hidden(reinterpret_cast<HANDLE>(pid));
}
inline bool is_monitored(ULONG_PTR pid) {
    return is_monitored(reinterpret_cast<HANDLE>(pid));
}

// --------------------------------------------------------------------------
// Classification queries — by PEPROCESS
// --------------------------------------------------------------------------
bool is_target(PEPROCESS process);
bool is_hidden(PEPROCESS process);
bool is_monitored(PEPROCESS process);

// --------------------------------------------------------------------------
// Classification queries — by raw name buffer
// --------------------------------------------------------------------------
bool is_target(PWCH name_buffer);
bool is_hidden(PWCH name_buffer);
bool is_monitored(PWCH name_buffer);

// --------------------------------------------------------------------------
// Convenience: check if the *current* process is a target/hidden/monitored
// --------------------------------------------------------------------------
inline bool current_is_target() {
    return is_target(PsGetCurrentProcessId());
}

inline bool current_is_hidden() {
    return is_hidden(PsGetCurrentProcessId());
}

inline bool current_is_monitored() {
    return is_monitored(PsGetCurrentProcessId());
}

// --------------------------------------------------------------------------
// Convenience: check current process via EPROCESS (avoids PID lookup)
// --------------------------------------------------------------------------
inline bool current_is_target_ex() {
    return is_target(PsGetCurrentProcess());
}

inline bool current_is_hidden_ex() {
    return is_hidden(PsGetCurrentProcess());
}

}  // namespace process_manager
