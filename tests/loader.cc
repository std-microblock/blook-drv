#include <array>
#include <initializer_list>
#include <string>
#include <string_view>

#include "loader/cli.hpp"
#include "loader/config.hpp"
#include "support.hpp"

namespace cli = blook::loader::cli;
namespace {
auto parse(std::initializer_list<std::wstring_view> args) {
    return cli::parse({args.begin(), args.size()});
}
void rejects(std::initializer_list<std::wstring_view> args) {
    const auto result = parse(args);
    test::check(!result, "malformed command rejected");
    test::check(
        !result.error().message.empty() && !result.error().usage.empty(),
        "parse failure includes explanation and usage");
}
}  // namespace

int main() {
    test::check(parse({})->action == cli::kind::help,
                "no arguments shows help");
    for (const auto name : {L"help", L"--help"})
        test::check(parse({name})->action == cli::kind::help, "help aliases");
    for (const auto name :
         {L"start", L"stop", L"uninstall", L"ping", L"version", L"status"}) {
        test::check(parse({name}).has_value(), "single command accepted");
        rejects({name, L"extra"});
        test::check(parse({name, L"--help"})->action == cli::kind::help,
                    "command help has no action");
    }
    rejects({L"unknown"});
    rejects({L"unknown", L"--help"});
    rejects({L"help", L"extra"});
    rejects({L"install"});
    rejects({L"install", L""});
    rejects({L"apply", L"a", L"b"});
    test::check(parse({L"install", LR"(D:\test folder\driver.sys)"})->path ==
                    LR"(D:\test folder\driver.sys)",
                "quoted path preserved");
    test::check(parse({L"apply"})->path == L"blook.ini",
                "default configuration path");
    test::check(parse({L"apply", L"配置.ini"})->path == L"配置.ini",
                "Unicode path preserved");
    // Construct an actual embedded NUL rather than an escaped path separator.
    std::wstring nul_path = L"bad";
    nul_path.push_back(L'\0');
    nul_path += L"path";
    rejects({L"install", nul_path});
    for (const auto text : {L"0", L"-1", L"+1", L"1junk", L" 1", L"1 ",
                            L"4294967296", L"0x10", L""}) {
        test::check(!cli::parse_pid(text), "invalid PID rejected");
        rejects({L"unpin", text});
    }
    test::check(*cli::parse_pid(L"4294967295") == 0xffffffffu, "maximum PID");
    test::check(
        parse({L"pin", L"target", L"42"})->process_role == cli::role::target,
        "typed role");
    rejects({L"pin", L"invalid", L"42"});
    rejects({L"scrub"});
    rejects({L"hide", L"yes"});
    rejects({L"hide", L"other", L"on"});
    test::check(parse({L"hide", L"windows", L"off"})->windows,
                "window mode parsed");
    test::check(!parse({L"hide", L"off"})->enable, "off mode parsed");
    for (const auto text : {L"", L"0", L"0x", L"GG", L"+1", L" 1", L"C3 90"})
        test::check(!cli::parse_bytes(text), "malformed bytes rejected");
    test::check(cli::parse_bytes(std::wstring(128, L'f'))->size() == 64,
                "maximum bytes accepted");
    test::check(!cli::parse_bytes(std::wstring(130, L'f')),
                "oversize bytes rejected");
    for (unsigned value = 0; value < 256; ++value) {
        constexpr std::wstring_view digits = L"0123456789abcdef";
        const std::array text{digits[value >> 4], digits[value & 15]};
        const auto bytes = cli::parse_bytes({text.data(), text.size()});
        test::check(bytes && bytes->size() == 1 && (*bytes)[0] == value,
                    "all hexadecimal byte pairs roundtrip");
    }
    rejects({L"hook", L"self", L"0", L"C3"});
    rejects({L"hook", L"self", L"10000000000000000", L"C3"});
    const auto hook = parse({L"hook", L"self", L"0X10000", L"C3"});
    test::check(hook && hook->pid == 0 && hook->address == 0x10000 &&
                    hook->bytes[0] == 0xc3,
                "typed command fields");

    test::check(cli::parse_config(L"").has_value(), "empty config accepted");
    const auto config = cli::parse_config(
        L"# comment\n[DEVICE]\r\nallow_users = "
        L"NO\n[hooks]\nhook_mask=0x1ff\nwindow_hook_mask=077\n[roles]\ntool=42,"
        L" debugger.exe; another.exe\ntarget=\n");
    test::check(
        config && config->allow_users == false && config->hook_mask == 511u &&
            config->window_hook_mask == 63u && config->tools.size() == 3,
        "config typed values and legacy delimiters");
    const auto invalid_config =
        cli::parse_config(L"[device]\nallow_users=maybe\n");
    test::check(!invalid_config && invalid_config.error().line == 2,
                "config error includes line number");
    for (const auto text :
         {L"[hooks]\nhook_mask=-1", L"[hooks]\nhook_mask=4294967296",
          L"[hooks]\nhook_mask=09", L"[roles]\ntool=0", L"[device", L"invalid"})
        test::check(!cli::parse_config(text),
                    "invalid known config value rejected");
    test::check(cli::parse_config(L"[future]\nsetting=anything").has_value(),
                "unknown keys retain legacy tolerance");
    test::check(!cli::parse_config(L"[roles]\ntool=-1"),
                "negative role PID rejected");
    test::check(!cli::parse_config(L"[roles]\ntool=+1"),
                "signed role PID rejected");
    std::wstring nul_config = L"# comment";
    nul_config.push_back(L'\0');
    test::check(!cli::parse_config(nul_config),
                "NUL rejected even inside comment");
    return test::finish();
}
