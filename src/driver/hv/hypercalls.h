#pragma once

#include "policy/integer.hpp"

namespace hv {
// Internal ring-0 ABI between the driver and its own hypervisor. It is not an
// authorization mechanism: `emulate_vmcall` additionally requires CPL 0, the
// exact VMCALL site and a kernel pointer for every pointer argument.
enum class operation : uint8_t {
    ping,
    stop,
    install,
    remove,
    refresh,
    // Call-original window. `window_begin` exposes the untouched page so a
    // hook handler can invoke the real function; `window_end` re-arms the
    // execute trap. Both only affect the logical processor they run on, which
    // is exactly the one executing the hook handler.
    window_begin,
    window_end,
};

inline constexpr uint64_t call_tag = 0x424c4f4f4b;

struct hypercall_input {
    uint64_t command{};
    uint64_t args[6]{};
    explicit hypercall_input(operation op) noexcept
        : command((call_tag << 8) | static_cast<uint8_t>(op)) {}
};

static_assert(sizeof(hypercall_input) == 56);
}  // namespace hv
