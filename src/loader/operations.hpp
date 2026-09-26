#pragma once
#include <optional>

#include "cli.hpp"

namespace blook::loader {
struct failure {
    std::string action;
    std::uint32_t code{};
    std::string detail;
    std::string hint;
};
struct dashboard {
    std::uint32_t client_abi{}, driver_abi{}, hooks{}, window_hooks{},
        backend_status{};
    bool running{}, enabled{}, hidden{};
};
// Operations publish semantic events, never terminal escapes or console output.
class output_sink {
   public:
    virtual ~output_sink() = default;
    virtual void message(std::string_view text) = 0;
    virtual void wait_for_enter() = 0;
};
struct operation_result {
    int exit_code{};
    std::optional<dashboard> status;
};
[[nodiscard]] std::expected<operation_result, failure> execute(
    const cli::command& command, output_sink& output);
[[nodiscard]] std::uint32_t client_abi() noexcept;
}  // namespace blook::loader
