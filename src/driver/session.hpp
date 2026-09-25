#pragma once
#include <ntifs.h>

#include "ipc/protocol.hpp"

namespace blook {
NTSTATUS initialize_sessions();
void shutdown_sessions();
NTSTATUS open_session(PIRP irp, PFILE_OBJECT file);
void cleanup_session(PFILE_OBJECT file);
void close_session(PFILE_OBJECT file);
NTSTATUS control_session(PIRP irp, PIO_STACK_LOCATION stack);
}  // namespace blook
