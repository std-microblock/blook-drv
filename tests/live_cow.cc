// Live regression for the copy-on-write rebind: an EPT hook on a *shared
// image page* must survive the page being privatized by VirtualProtect.
//
// Without the NtProtectVirtualMemory maintenance hook the arming EPT entry
// keeps pointing at the old shared physical page: the very first
// VirtualProtect(RWX) silently rebinds the virtual page to a fresh private
// page and the hook never faults again (the classic self-decrypting-shell
// move). With the maintenance hook in place the post-pass rebinds the hook
// to the new backing page before the service returns.
//
// Never part of the host-only test suite; needs the driver running.
#include <cstdio>

#include "client/ept.hpp"

// Lives in the image's .text: a shared copy-on-write page, exactly what a
// shell decrypts in place.
__declspec(noinline) int image_function() { return 7; }

int main() {
    auto session = blook::client::session::open();
    if (!session) {
        std::fprintf(stderr, "open failed: %lu\n", session.error().value());
        return 1;
    }
    auto* const fn = &image_function;
    if (fn() != 7)
        return 2;

    // mov eax,42; ret - must be self-contained: execution continues past the
    // covered instructions, so a patch without the ret falls into the middle
    // of the next function.
    const uint8_t replacement[] = {0xb8, 42, 0, 0, 0, 0xc3};
    auto hook = session->patch(reinterpret_cast<void*>(fn), replacement);
    if (!hook) {
        std::fprintf(stderr, "patch failed: %lu\n", hook.error().value());
        return 3;
    }
    if (fn() != 42) {
        std::fprintf(stderr, "FAIL: hook did not fire on the image page\n");
        return 4;
    }
    std::printf("  hook live on the image page: fn()=42\n");

    // The CoW trigger: making a shared image page writable privatizes it
    // inside this very VirtualProtect call.
    DWORD old{};
    auto* const page = reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(fn) & ~uintptr_t{0xfff});
    if (!VirtualProtect(page, 4096, PAGE_EXECUTE_READWRITE, &old)) {
        std::fprintf(stderr, "VirtualProtect failed: %lu\n", GetLastError());
        return 5;
    }
    VirtualProtect(page, 4096, PAGE_EXECUTE_READ, &old);
    std::printf("  image page cycled through RWX (copy-on-write)\n");

    // If the maintenance rebind worked, the hook moved to the private page
    // and still fires. Before the fix this returned 7.
    if (fn() != 42) {
        std::fprintf(stderr, "FAIL: hook lost to copy-on-write (fn()=7)\n");
        return 6;
    }
    std::printf("  hook still fires after copy-on-write: fn()=42\n");

    if (!hook->remove() || fn() != 7) {
        std::fprintf(stderr, "FAIL: remove/restore\n");
        return 7;
    }
    std::printf("PASS: EPT hook survived copy-on-write rebind\n");
    return 0;
}
