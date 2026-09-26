#pragma once
#include <cstdio>

#include "operations.hpp"

namespace blook::loader {
class terminal final : public output_sink {
    struct stream_state {
        void* handle{};
        unsigned long original_mode{};
        bool changed{}, color{};
    };
    stream_state out_, err_;
    static stream_state detect(unsigned long id);
    static void restore(const stream_state& state) noexcept;
    void heading(std::string_view title);
    void field(std::string_view label, std::string_view value);

   public:
    terminal();
    ~terminal() override;
    terminal(const terminal&) = delete;
    terminal& operator=(const terminal&) = delete;
    void help();
    void invalid(const cli::parse_error& error);
    void error(const failure& error);
    void status(const dashboard& status);
    void message(std::string_view text) override;
    void wait_for_enter() override;
};
}  // namespace blook::loader
