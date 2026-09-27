#include "loader/terminal.hpp"

#include <gtest/gtest.h>
#include <windows.h>

#include <string>
#include <string_view>

namespace {
// Offline rendering only: this target links no operations.cc and cannot reach
// SCM or the driver. Redirect both CRT streams and Win32 handles so a console
// host cannot bypass the capture through WriteConsoleW.
class TerminalTest : public ::testing::Test {
   protected:
    void SetUp() override {
        original_out_ = GetStdHandle(STD_OUTPUT_HANDLE);
        original_err_ = GetStdHandle(STD_ERROR_HANDLE);
        ::testing::internal::CaptureStdout();
        ::testing::internal::CaptureStderr();
        capturing_ = true;
        ASSERT_TRUE(SetStdHandle(STD_OUTPUT_HANDLE, INVALID_HANDLE_VALUE));
        ASSERT_TRUE(SetStdHandle(STD_ERROR_HANDLE, INVALID_HANDLE_VALUE));
    }

    void TearDown() override { finish_capture(); }

    void finish_capture() {
        if (!capturing_)
            return;
        out_ = ::testing::internal::GetCapturedStdout();
        err_ = ::testing::internal::GetCapturedStderr();
        // CRT descriptor restoration may itself affect standard handles;
        // restore the originals last, including on fatal test assertions.
        const auto restored_out =
            SetStdHandle(STD_OUTPUT_HANDLE, original_out_);
        const auto restored_err = SetStdHandle(STD_ERROR_HANDLE, original_err_);
        capturing_ = false;
        EXPECT_TRUE(restored_out);
        EXPECT_TRUE(restored_err);
    }

    void expect_field(std::string_view label, std::string_view value) {
        const auto position = out_.find("  " + std::string{label} + " ");
        ASSERT_NE(position, std::string::npos) << label;
        const auto end = out_.find('\n', position);
        const auto line = out_.substr(position, end - position);
        EXPECT_NE(line.find(value), std::string::npos) << line;
    }

    std::string out_;
    std::string err_;

   private:
    HANDLE original_out_{};
    HANDLE original_err_{};
    bool capturing_{};
};

TEST_F(TerminalTest, NormalStatusReportsMatchedRunningDriver) {
    {
        blook::loader::terminal output;
        output.status({.client_abi = 4,
                       .driver_abi = 4,
                       .hooks = 2,
                       .window_hooks = 0,
                       .backend_status = 0,
                       .running = true});
    }
    finish_capture();
    EXPECT_TRUE(err_.empty());
    EXPECT_NE(out_.find("BLOOK / DRIVER STATUS"), std::string::npos);
    EXPECT_NE(out_.find("[ RUNNING ]"), std::string::npos);
    EXPECT_EQ(out_.find("ABI MISMATCH"), std::string::npos);
    EXPECT_EQ(out_.find("Hint:"), std::string::npos);
    EXPECT_EQ(out_.find('\x1b'), std::string::npos);
    expect_field("Device", "Connected (query only)");
    expect_field("Client / driver ABI", "4 / 4");
    expect_field("ABI compatibility", "Matched");
    expect_field("VMX", "RUNNING");
    expect_field("Session enabled", "No");
    expect_field("Hooks (this process)", "2");
    expect_field("Hide profile", "Inactive");
    expect_field("Window hooks", "0");
    expect_field("Backend NTSTATUS", "0x00000000");
}

TEST_F(TerminalTest, DegradedStatusReportsMismatchAndBackendFailure) {
    {
        blook::loader::terminal output;
        output.status({.client_abi = 4,
                       .driver_abi = 3,
                       .hooks = 0,
                       .window_hooks = 0,
                       .backend_status = 0xc00000a3,
                       .running = false});
    }
    finish_capture();
    EXPECT_TRUE(err_.empty());
    EXPECT_NE(out_.find("[ NOT RUNNING ]"), std::string::npos);
    EXPECT_NE(out_.find("[ ABI MISMATCH ]"), std::string::npos);
    EXPECT_NE(out_.find("No automatic changes were made."), std::string::npos);
    EXPECT_EQ(out_.find('\x1b'), std::string::npos);
    expect_field("Client / driver ABI", "4 / 3");
    expect_field("ABI compatibility",
                 "MISMATCH - use matching client and driver");
    expect_field("VMX", "NOT RUNNING");
    expect_field("Hooks (this process)", "0");
    expect_field("Window hooks", "0");
    expect_field("Backend NTSTATUS", "0xC00000A3");
}

TEST_F(TerminalTest, UnicodeErrorIsUtf8OnStderrWithCodeAndHint) {
    {
        blook::loader::terminal output;
        output.error({"Offline fixture", 5, "Unicode: 中文路径",
                      "This is simulated; no device was opened."});
    }
    finish_capture();
    EXPECT_TRUE(out_.empty());
    EXPECT_NE(err_.find("Error: Offline fixture failed."), std::string::npos);
    EXPECT_NE(err_.find("Windows 5 (0x00000005): "), std::string::npos);
    EXPECT_NE(err_.find("Unicode: 中文路径"), std::string::npos);
    EXPECT_NE(err_.find("Hint: This is simulated; no device was opened."),
              std::string::npos);
    EXPECT_EQ(err_.find('\x1b'), std::string::npos);
    // The system description is localized, so do not assert its wording.
}
}  // namespace
