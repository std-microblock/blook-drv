// What does the hypervisor cost code that is *not* hooked?
//
// scripts/Bench.ps1 runs this three times - driver stopped, driver running with
// no profile, driver running with the hidden profile on - and logs all three
// together. The tests are split by what the mechanism can affect:
//
//   alu / call / memcpy : plain instruction streams, nothing intercepted
//   rdtsc / cpuid / qpc : instructions the hypervisor intercepts (vm-exit each)
//   syscall             : a syscall no hook covers
//   hooked call         : a user-mode EPT hook on this process own page
#include <client/ept.hpp>

#include <intrin.h>
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {

uint64_t now_ticks() { unsigned aux = 0; return __rdtscp(&aux); }

struct measurement {
    const char* name;
    uint64_t operations;
    double ns_per_op;
};

std::vector<measurement> results;

void record(const char* name, uint64_t operations, uint64_t ticks, double ticks_per_ns) {
    results.push_back({name, operations,
                       static_cast<double>(ticks) / ticks_per_ns /
                           static_cast<double>(operations)});
    std::printf("  %-16s %10llu ops  %8.2f ns/op\n", name,
                static_cast<unsigned long long>(operations), results.back().ns_per_op);
}

volatile uint64_t sink;

__declspec(noinline) uint64_t chain(uint64_t value) {
    for (int i = 0; i < 8; ++i) value = value * 6364136223846793005ull + 1442695040888963407ull;
    return value;
}

}  // namespace

int main(int argc, char** argv) {
    // --log <path>: append the whole report to a file as well. The runner
    // uses it because capturing a native program's console output from
    // PowerShell is unreliable on this machine.
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::strcmp(argv[i], "--log") == 0) {
            std::freopen(argv[i + 1], "a", stdout);   // the CRT flushes on exit
        }
    }

    LARGE_INTEGER frequency{};
    QueryPerformanceFrequency(&frequency);
    // __rdtscp counts TSC ticks, QPC counts its own units: calibrate one
    // against the other instead of assuming they are the same clock.
    double ticks_per_ns = 1.0;
    {
        LARGE_INTEGER before{}, after{};
        QueryPerformanceCounter(&before);
        const uint64_t t0 = now_ticks();
        Sleep(50);
        const uint64_t t1 = now_ticks();
        QueryPerformanceCounter(&after);
        const double ns = static_cast<double>(after.QuadPart - before.QuadPart) * 1e9 /
                          static_cast<double>(frequency.QuadPart);
        if (ns > 0) ticks_per_ns = static_cast<double>(t1 - t0) / ns;
    }

    auto session = blook::client::session::open(true);    // ENABLE is idempotent; a stopped driver has no device to open
    if (session) {
        auto info = session->query();
        std::printf("driver: ABI %u running=%u hooks=%u hidden=%u window hooks=%u\n",
                    info ? info->abi : 0, info ? info->running : 0, info ? info->hooks : 0,
                    info ? info->hidden : 0, info ? info->window_hooks : 0);
    } else {
        std::printf("driver: not reachable (%lu) - measuring the bare machine\n", session.error());
    }

    {   // plain code: nothing here is intercepted
        const uint64_t iterations = 20000000;
        uint64_t value = 1;
        const uint64_t start = now_ticks();
        for (uint64_t i = 0; i < iterations; ++i) {
            value = value * 2862933555777941757ull + 3037000493ull;
            value ^= value >> 29;
            value = (value << 7) | (value >> 57);
        }
        const uint64_t ticks = now_ticks() - start;
        sink = value;
        record("alu", iterations, ticks, ticks_per_ns);
    }
    {
        const uint64_t iterations = 3000000;
        uint64_t value = 1;
        const uint64_t start = now_ticks();
        for (uint64_t i = 0; i < iterations; ++i) value += chain(value);
        const uint64_t ticks = now_ticks() - start;
        sink = value;
        record("call", iterations, ticks, ticks_per_ns);
    }
    {
        const uint64_t iterations = 20000;
        std::vector<uint8_t> source(64 * 1024, 0x5a), target(64 * 1024, 0);
        const uint64_t start = now_ticks();
        for (uint64_t i = 0; i < iterations; ++i)
            std::memcpy(target.data(), source.data(), source.size());
        const uint64_t ticks = now_ticks() - start;
        sink = target[1234];
        record("memcpy64k", iterations, ticks, ticks_per_ns);
    }

    {   // intercepted instruction classes
        const uint64_t iterations = 300000;
        uint64_t value = 0;
        const uint64_t start = now_ticks();
        for (uint64_t i = 0; i < iterations; ++i) { unsigned aux = 0; value += __rdtscp(&aux); }
        const uint64_t ticks = now_ticks() - start;
        sink = value;
        record("rdtsc", iterations, ticks, ticks_per_ns);
    }
    {
        const uint64_t iterations = 200000;
        uint64_t value = 0;
        const uint64_t start = now_ticks();
        for (uint64_t i = 0; i < iterations; ++i) {
            int regs[4]{};
            __cpuidex(regs, 0, 0);
            value += static_cast<uint64_t>(regs[0]);
        }
        const uint64_t ticks = now_ticks() - start;
        sink = value;
        record("cpuid", iterations, ticks, ticks_per_ns);
    }
    {
        const uint64_t iterations = 500000;
        uint64_t value = 0;
        LARGE_INTEGER counter{};
        const uint64_t start = now_ticks();
        for (uint64_t i = 0; i < iterations; ++i) {
            QueryPerformanceCounter(&counter);
            value += static_cast<uint64_t>(counter.QuadPart);
        }
        const uint64_t ticks = now_ticks() - start;
        sink = value;
        record("qpc", iterations, ticks, ticks_per_ns);
    }

    {   // a syscall none of the hooks cover
        const uint64_t iterations = 200000;
        using query_system_time_t = long (*)(LARGE_INTEGER*);
        auto query_system_time = reinterpret_cast<query_system_time_t>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemTime"));
        if (query_system_time) {
            LARGE_INTEGER time{};
            const uint64_t start = now_ticks();
            for (uint64_t i = 0; i < iterations; ++i) query_system_time(&time);
            const uint64_t ticks = now_ticks() - start;
            sink = static_cast<uint64_t>(time.QuadPart);
            record("syscall", iterations, ticks, ticks_per_ns);
        } else {
            std::printf("  syscall          skipped (NtQuerySystemTime not found)\n");
        }
    }

    // a page this process hooks through the driver, if the backend is up
    bool backend_running = false;
    if (session) {
        auto info = session->query();
        backend_running = info && info->running;
    }
    if (backend_running) {
        auto* memory = static_cast<uint8_t*>(
            VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (memory) {
            const uint8_t original[] = {0xb8, 7, 0, 0, 0, 0xc3};   // mov eax,7; ret
            const uint8_t patch[] = {0xb8, 42, 0, 0, 0, 0xc3};     // mov eax,42; ret
            std::memcpy(memory, original, sizeof(original));
            DWORD old{};
            VirtualProtect(memory, 4096, PAGE_EXECUTE_READWRITE, &old);
            FlushInstructionCache(GetCurrentProcess(), memory, 4096);
            auto function = reinterpret_cast<int (*)()>(memory);
            const uint64_t iterations = 200000;

            uint64_t value = 0;
            uint64_t start = now_ticks();
            for (uint64_t i = 0; i < iterations; ++i) value += function();
            record("plain call", iterations, now_ticks() - start, ticks_per_ns);
            sink = value;

            if (auto hooked = session->patch(0, memory, patch)) {
                uint64_t check = 0;
                start = now_ticks();
                for (uint64_t i = 0; i < iterations; ++i) check += function();
                record("hooked call", iterations, now_ticks() - start, ticks_per_ns);
                sink = check;
                if (check != 42ull * iterations)
                    std::printf("  (hooked call returned the wrong value!)\n");

                // Same calls, but with one data read of the hooked page per
                // iteration: the data view has to be handed out first, so the
                // next instruction fetch traps again. This is the per-call
                // cost a target sees when it mixes code and data on the page.
                uint64_t mixed = 0;
                start = now_ticks();
                for (uint64_t i = 0; i < iterations; ++i) mixed += function() + memory[0];
                record("hooked mixed", iterations, now_ticks() - start, ticks_per_ns);
                sink = mixed;
                hooked->remove();
            } else {
                std::printf("  hooked call      skipped (patch failed: %lu)\n", hooked.error());
            }
            VirtualFree(memory, 0, MEM_RELEASE);
        }
    } else {
        std::printf("  hooked call      skipped (backend not running)\n");
    }

    std::printf("ratios (vs %s):\n", results.empty() ? "-" : results.front().name);
    for (const auto& m : results)
        std::printf("  %-16s x%6.2f\n", m.name,
                    results.empty() ? 0.0 : m.ns_per_op / results.front().ns_per_op);
    return 0;
}
