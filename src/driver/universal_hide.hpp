#pragma once

#include "Veil.h"
#include "core/expected.hpp"
#include "process_manager.hpp"

namespace hide {

namespace globals {
// Driver names to hide from module enumeration
extern const char* szProtectedDrivers[];
}  // namespace globals

namespace tools {
// OB callback patching helpers (internal to universal_hide.cc)
// Process name resolution is now in process_manager.
void DumpMZ(PUCHAR base);
void SwapEndianness(char* str, size_t size);
}  // namespace tools

// Hook registration function
core::VoidResult register_hooks();

}  // namespace hide
