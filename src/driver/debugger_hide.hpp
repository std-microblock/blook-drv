#pragma once

#include "core/expected.hpp"

namespace debugger_hide {

// Register all anti-debug SSDT hooks.
// Hooks the following syscalls to hide debugging artifacts from target
// processes:
//
//   NtQueryInformationProcess  — hides debug port / object / flags
//   NtSetInformationThread     — swallows ThreadHideFromDebugger
//   NtSetInformationProcess    — spoofs ProcessBreakOnTermination / DebugFlags
//   NtQueryObject              — adjusts DebugObject type counts
//   NtSystemDebugControl       — returns STATUS_DEBUGGER_INACTIVE
//   NtClose                    — prevents exception on invalid / protected handles
//   NtQuerySystemInformation   — hides kernel debugger info, strips processes / handles / pool tags
//   NtSetContextThread         — filters debug register writes
//   NtGetContextThread         — returns fake debug registers
//   NtQueryInformationThread   — spoofs ThreadHideFromDebugger / BreakOnTermination / Wow64Context
//   NtCreateThreadEx           — strips HIDE_FROM_DEBUGGER / BYPASS_PROCESS_FREEZE flags
//   NtCreateFile               — hides driver file handles
//   NtGetNextProcess           — skips hidden processes
//   NtOpenProcess              — blocks opening hidden processes
//   NtOpenThread               — blocks opening hidden process threads
//   NtYieldExecution           — always returns STATUS_SUCCESS
//   NtQueryInformationJobObject— strips hidden PIDs from job process lists
//   NtContinue                 — filters debug context on continuation
//
core::VoidResult register_hooks();

}  // namespace debugger_hide

