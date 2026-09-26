#include "loader/terminal.hpp"

// Offline rendering fixture. It links no operations.cc and cannot reach SCM or
// the driver. Used to inspect normal/degraded states without modifying a host.
int main() {
    blook::loader::terminal output;
    output.status({.client_abi = 4,
                   .driver_abi = 4,
                   .hooks = 2,
                   .window_hooks = 0,
                   .backend_status = 0,
                   .running = true});
    output.status({.client_abi = 4,
                   .driver_abi = 3,
                   .hooks = 0,
                   .window_hooks = 0,
                   .backend_status = 0xc00000a3,
                   .running = false});
    output.error({"Offline fixture", 5, "Unicode: 中文路径",
                  "This is simulated; no device was opened."});
    return 0;
}
