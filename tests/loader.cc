#include <gtest/gtest.h>

#include <array>
#include <initializer_list>
#include <string>
#include <string_view>

#include "loader/cli.hpp"
#include "loader/config.hpp"

namespace cli = blook::loader::cli;
namespace {
auto parse(std::initializer_list<std::wstring_view> args) {
    return cli::parse({args.begin(), args.size()});
}
void rejects(std::initializer_list<std::wstring_view> args) {
    const auto result = parse(args);
    ASSERT_TRUE((!result)) << "malformed command rejected";
    ASSERT_TRUE(
        (!result.error().message.empty() && !result.error().usage.empty()))
        << "parse failure includes explanation and usage";
}
}  // namespace

TEST(LoaderTest, EmptyArgumentsAndHelpAliasesShowHelp) {
    const auto empty = parse({});
    ASSERT_TRUE(empty.has_value());
    EXPECT_EQ(empty->action, cli::kind::help) << "no arguments shows help";
    for (const auto name : {L"help", L"--help"}) {
        const auto result = parse({name});
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->action, cli::kind::help) << "help aliases";
    }
}

TEST(LoaderTest, SingleCommandsAcceptNoArgumentsAndSupportHelp) {
    for (const auto name :
         {L"start", L"stop", L"uninstall", L"ping", L"version", L"status"}) {
        ASSERT_TRUE((parse({name}).has_value())) << "single command accepted";
        rejects({name, L"extra"});
        const auto help = parse({name, L"--help"});
        ASSERT_TRUE(help.has_value());
        EXPECT_EQ(help->action, cli::kind::help)
            << "command help has no action";
    }
}

TEST(LoaderTest, MalformedCommandsIncludeExplanationAndUsage) {
    rejects({L"unknown"});
    rejects({L"unknown", L"--help"});
    rejects({L"help", L"extra"});
    rejects({L"install"});
    rejects({L"install", L""});
    rejects({L"apply", L"a", L"b"});
}

TEST(LoaderTest, InstallPreservesQuotedPath) {
    const auto result = parse({L"install", LR"(D:\test folder\driver.sys)"});
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->path, LR"(D:\test folder\driver.sys)")
        << "quoted path preserved";
}

TEST(LoaderTest, ApplyUsesDefaultAndPreservesUnicodePath) {
    const auto defaults = parse({L"apply"});
    ASSERT_TRUE(defaults.has_value());
    EXPECT_EQ(defaults->path, L"blook.ini") << "default configuration path";
    const auto unicode = parse({L"apply", L"配置.ini"});
    ASSERT_TRUE(unicode.has_value());
    EXPECT_EQ(unicode->path, L"配置.ini") << "Unicode path preserved";
}

TEST(LoaderTest, InstallRejectsEmbeddedNul) {
    // Construct an actual embedded NUL rather than an escaped path separator.
    std::wstring nul_path = L"bad";
    nul_path.push_back(L'\0');
    nul_path += L"path";
    rejects({L"install", nul_path});
}

TEST(LoaderTest, PidRejectsInvalidInputsAndAcceptsMaximum) {
    for (const auto text : {L"0", L"-1", L"+1", L"1junk", L" 1", L"1 ",
                            L"4294967296", L"0x10", L""}) {
        ASSERT_TRUE((!cli::parse_pid(text))) << "invalid PID rejected";
        rejects({L"unpin", text});
    }
    const auto maximum = cli::parse_pid(L"4294967295");
    ASSERT_TRUE(maximum.has_value());
    EXPECT_EQ(*maximum, 0xffffffffu) << "maximum PID";
}

TEST(LoaderTest, PinParsesTypedRoleAndRejectsInvalidRole) {
    const auto result = parse({L"pin", L"target", L"42"});
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->process_role, cli::role::target) << "typed role";
    rejects({L"pin", L"invalid", L"42"});
}

TEST(LoaderTest, ScrubRequiresArguments) {
    rejects({L"scrub"});
}

TEST(LoaderTest, HideValidatesArgumentsAndParsesModes) {
    rejects({L"hide", L"yes"});
    rejects({L"hide", L"other", L"on"});
    const auto windows = parse({L"hide", L"windows", L"off"});
    ASSERT_TRUE(windows.has_value());
    EXPECT_TRUE(windows->windows) << "window mode parsed";
    const auto off = parse({L"hide", L"off"});
    ASSERT_TRUE(off.has_value());
    EXPECT_FALSE(off->enable) << "off mode parsed";
}

TEST(LoaderTest, BytesRejectMalformedAndOversizedInputs) {
    for (const auto text : {L"", L"0", L"0x", L"GG", L"+1", L" 1", L"C3 90"})
        ASSERT_TRUE((!cli::parse_bytes(text))) << "malformed bytes rejected";
    const auto maximum = cli::parse_bytes(std::wstring(128, L'f'));
    ASSERT_TRUE(maximum.has_value());
    EXPECT_EQ(maximum->size(), 64u) << "maximum bytes accepted";
    ASSERT_TRUE((!cli::parse_bytes(std::wstring(130, L'f'))))
        << "oversize bytes rejected";
}

TEST(LoaderTest, EveryHexadecimalBytePairRoundTrips) {
    for (unsigned value = 0; value < 256; ++value) {
        constexpr std::wstring_view digits = L"0123456789abcdef";
        const std::array text{digits[value >> 4], digits[value & 15]};
        const auto bytes = cli::parse_bytes({text.data(), text.size()});
        ASSERT_TRUE((bytes && bytes->size() == 1 && (*bytes)[0] == value))
            << "all hexadecimal byte pairs roundtrip";
    }
}

TEST(LoaderTest, HookValidatesAddressAndParsesTypedFields) {
    rejects({L"hook", L"self", L"0", L"C3"});
    rejects({L"hook", L"self", L"10000000000000000", L"C3"});
    const auto hook = parse({L"hook", L"self", L"0X10000", L"C3"});
    ASSERT_TRUE((hook && hook->pid == 0 && hook->address == 0x10000 &&
                 hook->bytes[0] == 0xc3))
        << "typed command fields";
}

TEST(LoaderTest, EmptyConfigurationIsAccepted) {
    ASSERT_TRUE((cli::parse_config(L"").has_value()))
        << "empty config accepted";
}

TEST(LoaderTest, ConfigurationParsesTypedValuesAndLegacyDelimiters) {
    const auto config = cli::parse_config(
        L"# comment\n[DEVICE]\r\nallow_users = "
        L"NO\n[hooks]\nhook_mask=0x1ff\nwindow_hook_mask=077\n[roles]\ntool=42,"
        L" debugger.exe; another.exe\ntarget=\n");
    ASSERT_TRUE((config && config->allow_users == false &&
                 config->hook_mask == 511u && config->window_hook_mask == 63u &&
                 config->tools.size() == 3))
        << "config typed values and legacy delimiters";
}

TEST(LoaderTest, ConfigurationErrorIncludesLineNumber) {
    const auto invalid_config =
        cli::parse_config(L"[device]\nallow_users=maybe\n");
    ASSERT_TRUE((!invalid_config && invalid_config.error().line == 2))
        << "config error includes line number";
}

TEST(LoaderTest, ConfigurationRejectsInvalidKnownValues) {
    for (const auto text :
         {L"[hooks]\nhook_mask=-1", L"[hooks]\nhook_mask=4294967296",
          L"[hooks]\nhook_mask=09", L"[roles]\ntool=0", L"[device", L"invalid"})
        ASSERT_TRUE((!cli::parse_config(text)))
            << "invalid known config value rejected";
}

TEST(LoaderTest, ConfigurationToleratesUnknownKeys) {
    ASSERT_TRUE((cli::parse_config(L"[future]\nsetting=anything").has_value()))
        << "unknown keys retain legacy tolerance";
}

TEST(LoaderTest, ConfigurationRejectsSignedRolePids) {
    ASSERT_TRUE((!cli::parse_config(L"[roles]\ntool=-1")))
        << "negative role PID rejected";
    ASSERT_TRUE((!cli::parse_config(L"[roles]\ntool=+1")))
        << "signed role PID rejected";
}

TEST(LoaderTest, ConfigurationRejectsNulInsideComment) {
    std::wstring nul_config = L"# comment";
    nul_config.push_back(L'\0');
    ASSERT_TRUE((!cli::parse_config(nul_config)))
        << "NUL rejected even inside comment";
}
