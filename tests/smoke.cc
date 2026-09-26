#include <atomic>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

#include "client/ept.hpp"
int main() {
    auto session = blook::client::session::open();
    if (!session) {
        std::fprintf(stderr,
                     "Open failed: %lu. Run elevated on an isolated supported "
                     "Intel machine with the test-signed driver loaded.\n",
                     session.error());
        return 1;
    }
    auto memory = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!memory)
        return 1;
    const uint8_t original[] = {0xb8, 7, 0, 0, 0, 0xc3};  // mov eax,7; ret
    std::memcpy(memory, original, sizeof(original));
    DWORD old{};
    if (!VirtualProtect(memory, 4096, PAGE_EXECUTE_READWRITE, &old))
        return 1;
    FlushInstructionCache(GetCurrentProcess(), memory, 4096);
    auto function = reinterpret_cast<int (*)()>(memory);
    if (function() != 7)
        return 2;
    const uint8_t replacement[] = {0xb8, 42, 0, 0, 0, 0xc3};
    auto hook = session->patch(memory, replacement);
    if (!hook) {
        std::fprintf(stderr, "Install failed: %lu\n", hook.error());
        VirtualFree(memory, 0, MEM_RELEASE);
        return 3;
    }
    std::atomic<bool> good{true};
    std::atomic<unsigned> bad_execute{0}, bad_data{0}, bad_original{0};
    std::vector<std::thread> threads;
    for (unsigned i = 0; i < 4; ++i)
        threads.emplace_back([&] {
            for (unsigned j = 0; j < 10000; ++j) {
                if (function() != 42) {
                    bad_execute.fetch_add(1);
                    good.store(false);
                }
                if (std::memcmp(memory, original, sizeof(original))) {
                    bad_data.fetch_add(1);
                    good.store(false);
                }
            }
        });
    for (auto& t : threads)
        t.join();
    std::printf("  after patch: calls=%d/40000 wrong, data-view-wrong=%d, function()=%d (want 42), memory[0..5]=",
                bad_execute.load(), bad_data.load(), static_cast<int>(function()));
    for (unsigned i = 0; i < sizeof(original); ++i)
        std::printf("%02x ", memory[i]);
    std::printf("(want ");
    for (unsigned i = 0; i < sizeof(original); ++i)
        std::printf("%02x ", original[i]);
    std::printf(")\n");
    // A data write updates the original; an explicit refresh republishes its
    // snapshot.
    memory[64] = 0x5a;
    auto refreshed = hook->refresh();
    std::printf("  refresh: ok=%d memory[64]=0x%02x (want 0x5a) function()=%d (want 42)",
                refreshed ? 1 : 0, memory[64], static_cast<int>(function()));
    std::printf("\n");
    if (!refreshed || memory[64] != 0x5a || function() != 42)
        good = false;
    const auto removed = hook->remove();
    std::printf("  remove: ok=%d function()=%d (want 7)", removed ? 1 : 0,
                static_cast<int>(function()));
    std::printf("\n");
    if (!removed || function() != 7)
        good = false;
    VirtualFree(memory, 0, MEM_RELEASE);
    std::printf(
        "%s: original data / shadow execution / MTF / refresh / removal\n",
        good ? "PASS" : "FAIL");
    return good ? 0 : 4;
}
