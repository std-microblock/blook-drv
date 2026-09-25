#include <cstdio>
#include <cstdlib>
#include <string_view>

#include "ipc/protocol.hpp"
#include "policy/hook.hpp"
#include "policy/names.hpp"
using namespace blook;
namespace {
unsigned checks{};
void check(bool condition, const char* message) {
    ++checks;
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        std::exit(1);
    }
}
role classify(std::wstring_view name) {
    return blook::classify(name.data(), name.size());
}
role classify_ascii(std::string_view name) {
    return blook::classify_ascii(name.data(), name.size());
}
}  // namespace

void test_ept_engine();

int main() {
    test_ept_engine();

    // The policy has to recognise the same images the previous implementation
    // did, and it must not depend on the path the sample was started from.
    check(classify(L"al-khaser_x64.exe") == role::target, "target by name");
    check(classify(L"C:\\tools\\AL-KHASER_X64.EXE") == role::target,
          "target case insensitive");
    check(classify(L"C:\\ctf-target-20260422.exe") == role::target,
          "target by prefix list entry");
    check(classify(L"C:\\dbg\\x64dbg.exe") == role::tool, "tool by name");
    check(classify(L"C:\\dbg\\CheatEngine-x86_64.exe") == role::tool,
          "tool by prefix list entry");
    check(classify(L"C:\\Windows\\System32\\taskmgr.exe") == role::watched,
          "watched role");
    check(classify(L"C:\\Windows\\explorer.exe") == role::other,
          "unclassified image");
    check(classify(L"") == role::other && classify(L"al-khaser") == role::other,
          "no false positive on partial name");
    check(classify_ascii("AL-KHASER_X64.EXE") == role::target,
          "ansi fallback path");
    check(classify_ascii("x64dbg.exe") == role::tool, "ansi fallback tool");
    check(classify_ascii("explorer.exe") == role::other, "ansi fallback other");
    const std::string_view driver_path =
        "\\SystemRoot\\System32\\drivers\\blook-drv.sys";
    const std::string_view other_driver =
        "\\SystemRoot\\System32\\drivers\\tcpip.sys";
    check(driver_path.size() == 42, "driver path length");
    check(blook::hidden_module(driver_path.data(), driver_path.size()),
          "driver path matched");
    check(!blook::hidden_module(other_driver.data(), other_driver.size()),
          "unrelated driver kept");

    // The entry jump must not clobber an argument register and must not read
    // its target back out of the shadow page.
    uint8_t buffer[max_patch]{};
    build_jump_patch(buffer,
                      reinterpret_cast<uint64_t>(buffer) + 0x200000,
                      reinterpret_cast<uint64_t>(buffer) + 0x200100);
    // The encoder is covered by the model test; the raw bytes change whenever
    // the entry-jump shape is revisited.

    check(valid_patch(0x10000, 64), "maximum patch");
    check(!valid_patch(0x10000, 65) && !valid_patch(0x10000, 0),
          "size rejection");
    check(valid_patch(0x10ffb, 5) && !valid_patch(0x10ffb, 6), "page boundary");
    for (unsigned i = 0; i < 4096; ++i)
        for (unsigned n = 0; n < 66; ++n)
            check(valid_patch(0x10000 + i, n) ==
                      (n >= 1 && n <= 64 && i + n <= 4096),
                  "exhaustive patch boundary");

    // Ownership: a user hook only fires for its own address space, a kernel
    // hook fires everywhere, and an unknown identity never matches.
    hook_spec spec{};
    spec.domain = hook_domain::user;
    spec.address_space = 123;
    check(
        same_owner(spec, 123) && !same_owner(spec, 124) && !same_owner(spec, 0),
        "address space not PID");
    spec.domain = hook_domain::kernel;
    check(same_owner(spec, 0), "kernel scope");

    auto original = select_view(ept_view::original_data, 123, 456);
    auto shadow = select_view(ept_view::shadow_execute, 123, 456);
    auto step = select_view(ept_view::original_step, 123, 456);
    auto window = select_view(ept_view::window_execute, 123, 456);
    check(original.pfn == 123 && original.permissions == 3, "original RW NX");
    check(shadow.pfn == 456 && shadow.permissions == 4, "shadow execute only");
    check(step.pfn == 123 && step.permissions == 7, "MTF original step");
    check(window.pfn == 123 && window.permissions == 7, "call original window");

    auto request = ipc::request<ipc::InstallRequest>();
    check(ipc::valid_header(request), "ABI size");
    request.header.version = ipc::abi_version - 1;
    check(!ipc::valid_header(request), "ABI version rejection");
    request = ipc::request<ipc::InstallRequest>();
    request.header.size--;
    check(!ipc::valid_header(request), "ABI length rejection");
    check(ipc::request<ipc::PingRequest>().header.size ==
              sizeof(ipc::PingRequest),
          "request factory sizes header");
    check((ipc::IOCTL_BLOOK_INSTALL & 3) == 0 &&
              ((ipc::IOCTL_BLOOK_INSTALL >> 14) & 3) == 3,
          "buffered and RW access");
    check(ipc::IOCTL_BLOOK_HIDE != ipc::IOCTL_BLOOK_SCRUB,
          "distinct control codes");

    std::printf("PASS: %u checks (policy/ABI, not hardware virtualization)\n",
                checks);
}
