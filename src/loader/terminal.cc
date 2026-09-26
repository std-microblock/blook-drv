#include "terminal.hpp"

#include <windows.h>

#include <array>
#include <cstdlib>

namespace blook::loader {
namespace {
// Keep redirected bytes UTF-8 and use Unicode console output without changing
// the process-wide console code page (including localized Windows errors).
void write(FILE* stream, std::string_view text) {
    if (text.empty())
        return;
    const auto handle =
        GetStdHandle(stream == stderr ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE);
    DWORD mode{};
    if (GetConsoleMode(handle, &mode) &&
        text.size() <=
            static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
        const auto count = MultiByteToWideChar(
            CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
        if (count > 0) {
            std::wstring wide(static_cast<std::size_t>(count), L'\0');
            MultiByteToWideChar(CP_UTF8, 0, text.data(),
                                static_cast<int>(text.size()), wide.data(),
                                count);
            std::fflush(stream);
            std::size_t offset{};
            while (offset < wide.size()) {
                DWORD written{};
                const auto remaining = wide.size() - offset;
                const auto chunk =
                    static_cast<DWORD>(remaining > 16384 ? 16384 : remaining);
                if (!WriteConsoleW(handle, wide.data() + offset, chunk,
                                   &written, nullptr) ||
                    !written)
                    return;
                offset += written;
            }
            return;
        }
    }
    std::fwrite(text.data(), 1, text.size(), stream);
}
void line(FILE* stream, std::string_view text) {
    write(stream, text);
    write(stream, "\n");
}
void styled(FILE* stream, bool color, const char* style,
            std::string_view text) {
    if (color)
        write(stream, style);
    write(stream, text);
    if (color)
        write(stream, "\x1b[0m");
}
std::string system_message(std::uint32_t code) {
    std::array<wchar_t, 2048> wide{};
    const auto length = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
        code, 0, wide.data(), static_cast<DWORD>(wide.size()), nullptr);
    if (!length)
        return "No system description available.";
    const auto count =
        WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(length),
                            nullptr, 0, nullptr, nullptr);
    if (!count)
        return "No system description available.";
    std::string text(static_cast<std::size_t>(count), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(length),
                        text.data(), count, nullptr, nullptr);
    while (!text.empty() &&
           (text.back() == '\r' || text.back() == '\n' || text.back() == ' '))
        text.pop_back();
    return text;
}
}  // namespace

terminal::stream_state terminal::detect(unsigned long id) {
    stream_state state;
    state.handle = GetStdHandle(id);
    // An existing NO_COLOR variable, even empty, disables styling. Check each
    // stream independently: redirected stdout must not affect console stderr.
    SetLastError(ERROR_SUCCESS);
    const auto no_color_length =
        GetEnvironmentVariableW(L"NO_COLOR", nullptr, 0);
    const bool no_color =
        no_color_length != 0 || GetLastError() != ERROR_ENVVAR_NOT_FOUND;
    if (no_color || !GetConsoleMode(state.handle, &state.original_mode))
        return state;
    const auto desired =
        state.original_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    if (desired == state.original_mode ||
        SetConsoleMode(state.handle, desired)) {
        state.color = true;
        state.changed = desired != state.original_mode;
    }
    return state;
}
void terminal::restore(const stream_state& state) noexcept {
    if (state.changed)
        SetConsoleMode(state.handle, state.original_mode);
}
terminal::terminal()
    : out_(detect(STD_OUTPUT_HANDLE)), err_(detect(STD_ERROR_HANDLE)) {}
terminal::~terminal() {
    restore(err_);
    restore(out_);
}
void terminal::heading(std::string_view title) {
    write(stdout, "\n");
    styled(stdout, out_.color, "\x1b[1;36m", title);
    write(stdout, "\n");
}
void terminal::field(std::string_view label, std::string_view value) {
    write(stdout,
          "  " + std::string{label} +
              std::string(label.size() < 22 ? 23 - label.size() : 1, ' '));
    line(stdout, value);
}
void terminal::help() {
    heading("BLOOK / Intel EPT analysis driver");
    line(stdout, "  Usage: blook-loader <command> [arguments]");
    line(stdout, "  Start here: blook-loader status   |   blook-loader --help");
    heading("INSPECT  /  read-only queries");
    field("status", "Readable driver dashboard; never starts VMX");
    field("ping", "Check device status; never starts VMX");
    field("version", "Print client ABI, then query driver status");
    field("help, --help", "Show this help without opening the device");
    heading("SERVICE  /  explicit system changes");
    field("install <signed.sys>", "Register a signed driver; do not start it");
    field("start | stop", "Start the service or wait up to 30s for stop");
    field("uninstall", "Remove a stopped service; keep the driver file");
    heading("CONFIGURATION");
    field("apply [blook.ini]",
          "Validate UTF-8 settings, then apply explicitly");
    heading("SESSION  /  existing advanced commands");
    line(stdout, "  hide on|off                  hide windows on|off");
    line(stdout, "  pin tool|target <pid>         unpin <pid>");
    line(stdout, "  scrub <pid>");
    line(stdout, "  hook <self|pid> <hex-address> <hex-bytes>");
    heading("NOTES");
    line(
        stdout,
        "  No arguments shows help; nothing is installed, started or applied.");
    line(stdout,
         "  Command --help is also supported. Quote paths containing spaces.");
    line(stdout,
         "  Session commands need a running driver and appropriate "
         "permissions.");
    line(stdout,
         "  PID: decimal 1..4294967295. Hook bytes: 1..64 hex pairs, no "
         "spaces.");
    line(stdout,
         "  Colors: automatic for supported consoles; NO_COLOR disables them.");
    line(stdout,
         "  Redirected output is plain text. Windows signing policy is "
         "unchanged.");
    line(stdout,
         "  Exit: 0 success/help; 1 input or operation error; 2 VMX not "
         "running.");
    write(stdout, "\n");
}
void terminal::invalid(const cli::parse_error& error) {
    styled(stderr, err_.color, "\x1b[1;31m", "Error: ");
    line(stderr, error.message);
    write(stderr, "Usage: blook-loader ");
    line(stderr, error.usage);
    line(stderr, "Hint: run blook-loader --help. No device was opened.");
}
void terminal::error(const failure& error) {
    styled(stderr, err_.color, "\x1b[1;31m", "Error: ");
    line(stderr, error.action + " failed.");
    if (error.code) {
        char code[48]{};
        std::snprintf(code, sizeof(code), "  Windows %lu (0x%08lX): ",
                      static_cast<unsigned long>(error.code),
                      static_cast<unsigned long>(error.code));
        write(stderr, code);
        line(stderr, system_message(error.code));
    }
    if (!error.detail.empty())
        line(stderr, "  " + error.detail);
    if (!error.hint.empty())
        line(stderr, "Hint: " + error.hint);
}
void terminal::status(const dashboard& view) {
    heading("BLOOK / DRIVER STATUS");
    styled(stdout, out_.color, view.running ? "\x1b[1;32m" : "\x1b[1;31m",
           view.running ? "  [ RUNNING ]" : "  [ NOT RUNNING ]");
    if (view.client_abi != view.driver_abi)
        styled(stdout, out_.color, "\x1b[1;31m", "  [ ABI MISMATCH ]");
    write(stdout, "\n\n");
    field("Device", "Connected (query only)");
    field("Client / driver ABI", std::to_string(view.client_abi) + " / " +
                                     std::to_string(view.driver_abi));
    field("ABI compatibility",
          view.client_abi == view.driver_abi
              ? "Matched"
              : "MISMATCH - use matching client and driver");
    heading("RUNTIME");
    field("VMX", view.running ? "RUNNING" : "NOT RUNNING");
    field("Session enabled", view.enabled ? "Yes" : "No");
    field("Hooks (this process)", std::to_string(view.hooks));
    field("Hide profile", view.hidden ? "Active" : "Inactive");
    field("Window hooks", std::to_string(view.window_hooks));
    char backend[11]{};
    std::snprintf(backend, sizeof(backend), "0x%08lX",
                  static_cast<unsigned long>(view.backend_status));
    field("Backend NTSTATUS", backend);
    write(stdout, "\n");
    if (!view.running)
        line(stdout,
             "  Hint: inspect the backend status and driver setup. No "
             "automatic changes were made.");
}
void terminal::message(std::string_view text) {
    line(stdout, text);
    std::fflush(stdout);
}
void terminal::wait_for_enter() {
    message("Press Enter to remove it (end-of-input also releases the hook).");
    for (int ch = std::getchar(); ch != '\n' && ch != EOF;
         ch = std::getchar()) {
    }
}
}  // namespace blook::loader
