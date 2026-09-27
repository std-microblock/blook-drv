// Live end-to-end test of the execute-watch (dump-on-execute) API against the
// real driver. Self-hosted, exactly like the ept smoke: this process allocates
// an RWX page with a marker function, arms a watch on its entry, then calls
// it. The hypervisor dumps the page out of physical memory on the first fetch;
// the test compares the dump with the bytes in memory.
//
// Requires the test-signed driver to be loaded and running. Never part of the
// host-only test suite.
#include <cstdio>
#include <cstring>
#include <thread>

#include "client/ept.hpp"

int main() {
    auto session = blook::client::session::open();
    if (!session) {
        std::fprintf(stderr,
                     "open failed: %lu (run elevated, driver running)\n",
                     session.error());
        return 1;
    }

    auto* memory = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!memory)
        return 2;
    const uint8_t code[] = {0xb8, 0x39, 0x5, 0, 0, 0xc3};  // mov eax,1337; ret
    std::memcpy(memory, code, sizeof(code));
    for (size_t i = 0x40; i < 4096; ++i)
        memory[i] = static_cast<uint8_t>(i * 13);
    DWORD old{};
    if (!VirtualProtect(memory, 4096, PAGE_EXECUTE_READWRITE, &old))
        return 3;
    FlushInstructionCache(GetCurrentProcess(), memory, 4096);
    auto* marker = reinterpret_cast<int (*)()>(memory);
    if (marker() != 1337)
        return 4;

    // 1) Before the hit, poll says pending and dump() is not ready.
    auto watch = session->watch_execute(memory, memory, 4096);
    if (!watch) {
        std::fprintf(stderr, "arm failed: %lu\n", watch.error());
        return 5;
    }
    const auto pending = watch->poll();
    if (!pending || pending->ready) {
        std::fprintf(stderr, "FAIL: poll before hit reports ready=%d\n",
                     pending ? int(pending->ready) : -1);
        return 6;
    }
    if (watch->dump()) {
        std::fprintf(stderr, "FAIL: dump before hit succeeded\n");
        return 7;
    }

    // 2) Execute the watched address: the dump is taken from physical memory.
    if (marker() != 1337)
        return 8;
    bool ready = false;
    blook::client::watch_hit hit{};
    for (unsigned i = 0; i < 100 && !ready; ++i) {
        auto polled = watch->poll();
        if (polled && polled->ready) {
            ready = true;
            hit = *polled;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
    if (!ready) {
        std::fprintf(stderr, "FAIL: watch never fired\n");
        return 9;
    }
    std::printf("  hit: rip=0x%llx cr3=0x%llx total=%llu\n", hit.rip, hit.cr3,
                hit.total);
    if (hit.rip != reinterpret_cast<uint64_t>(memory) || hit.total != 4096)
        return 10;
    const auto dump = watch->dump();
    if (!dump || dump->size() != 4096) {
        std::fprintf(stderr, "FAIL: dump fetch (size=%llu)\n",
                     dump ? unsigned long long(dump->size()) : 0ull);
        return 11;
    }
    if (std::memcmp(dump->data(), memory, 4096) != 0) {
        std::fprintf(stderr, "FAIL: dump bytes diverge from memory\n");
        return 12;
    }
    std::printf("  dump matches the page byte for byte (%zu bytes)\n",
                dump->size());

    // 3) The code keeps running unarmed after the one-shot hit.
    for (unsigned i = 0; i < 10000; ++i)
        if (marker() != 1337) {
            std::fprintf(stderr, "FAIL: marker() changed after hit at i=%u\n",
                         i);
            return 13;
        }
    std::printf("  loop intact, disarming...\n");
    const auto disarmed = watch->disarm();
    std::printf("  disarm result=%d\n", disarmed ? 1 : 0);
    VirtualFree(memory, 0, MEM_RELEASE);
    if (!disarmed) {
        std::fprintf(stderr, "FAIL: disarm error=%lu\n",
                     disarmed.error().value());
        return 14;
    }
    std::printf("PASS: execute watch dumped from physical memory on hit\n");
    return 0;
}
