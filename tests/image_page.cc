// Regression: two entry hooks sharing one bcrypt.dll image page. The driver
// path is deliberately opt-in; the ordinary CBC baseline never opens a session.
#include <windows.h>
#include <bcrypt.h>
#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <optional>
#include <type_traits>
#include <vector>

#include "client/ept.hpp"

namespace {

using SetProperty = decltype(&BCryptSetProperty);
using GenerateKey = decltype(&BCryptGenerateSymmetricKey);
SetProperty original_property = nullptr;
GenerateKey original_generate = nullptr;
std::atomic<unsigned long> property_hits{0}, generate_hits{0};

NTSTATUS WINAPI property_handler(BCRYPT_HANDLE object, LPCWSTR property,
                                 PUCHAR input, ULONG input_size, ULONG flags) {
    property_hits.fetch_add(1, std::memory_order_relaxed);
    return original_property(object, property, input, input_size, flags);
}

NTSTATUS WINAPI generate_handler(BCRYPT_ALG_HANDLE algorithm,
                                 BCRYPT_KEY_HANDLE* key, PUCHAR key_object,
                                 ULONG key_object_size, PUCHAR secret,
                                 ULONG secret_size, ULONG flags) {
    generate_hits.fetch_add(1, std::memory_order_relaxed);
    return original_generate(algorithm, key, key_object, key_object_size,
                             secret, secret_size, flags);
}
static_assert(std::is_same_v<decltype(&property_handler), SetProperty>);
static_assert(std::is_same_v<decltype(&generate_handler), GenerateKey>);

struct Algorithm {
    BCRYPT_ALG_HANDLE value = nullptr;
    ~Algorithm() {
        if (value)
            BCryptCloseAlgorithmProvider(value, 0);
    }
};
struct Key {
    BCRYPT_KEY_HANDLE value = nullptr;
    ~Key() {
        if (value)
            BCryptDestroyKey(value);
    }
};

::testing::AssertionResult cbc_roundtrip() {
    Algorithm algorithm;
    auto status = BCryptOpenAlgorithmProvider(&algorithm.value,
                                              BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status < 0)
        return ::testing::AssertionFailure()
               << "BCryptOpenAlgorithmProvider: " << status;
    status = BCryptSetProperty(
        algorithm.value, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
        static_cast<ULONG>((std::wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) *
                           sizeof(wchar_t)),
        0);
    if (status < 0)
        return ::testing::AssertionFailure() << "BCryptSetProperty: " << status;

    ULONG object_size = 0, returned = 0;
    status = BCryptGetProperty(algorithm.value, BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&object_size),
                               sizeof(object_size), &returned, 0);
    if (status < 0 || returned != sizeof(object_size) || object_size == 0)
        return ::testing::AssertionFailure()
               << "BCRYPT_OBJECT_LENGTH: " << status;
    // The key object must outlive the key handle, including early returns.
    std::vector<UCHAR> object(object_size);
    Key key;
    std::array<UCHAR, 16> secret{}, initial_iv{};
    std::array<UCHAR, 32> plaintext{}, ciphertext{}, recovered{};
    for (size_t i = 0; i < secret.size(); ++i) {
        secret[i] = static_cast<UCHAR>(0xa0 + i);
        initial_iv[i] = static_cast<UCHAR>(0x10 + i);
    }
    for (size_t i = 0; i < plaintext.size(); ++i)
        plaintext[i] = static_cast<UCHAR>(i * 3 + 1);
    status = BCryptGenerateSymmetricKey(
        algorithm.value, &key.value, object.data(), object_size, secret.data(),
        static_cast<ULONG>(secret.size()), 0);
    if (status < 0)
        return ::testing::AssertionFailure()
               << "BCryptGenerateSymmetricKey: " << status;

    // BCryptEncrypt mutates its IV. Decryption needs the same INITIAL IV,
    // not the IV left behind by encryption.
    auto encrypt_iv = initial_iv;
    auto decrypt_iv = initial_iv;
    ULONG encrypted_size = 0, decrypted_size = 0;
    status = BCryptEncrypt(
        key.value, plaintext.data(), static_cast<ULONG>(plaintext.size()),
        nullptr, encrypt_iv.data(), static_cast<ULONG>(encrypt_iv.size()),
        ciphertext.data(), static_cast<ULONG>(ciphertext.size()),
        &encrypted_size, 0);
    if (status < 0 || encrypted_size != plaintext.size())
        return ::testing::AssertionFailure()
               << "BCryptEncrypt: " << status << ", length=" << encrypted_size;
    status =
        BCryptDecrypt(key.value, ciphertext.data(), encrypted_size, nullptr,
                      decrypt_iv.data(), static_cast<ULONG>(decrypt_iv.size()),
                      recovered.data(), static_cast<ULONG>(recovered.size()),
                      &decrypted_size, 0);
    if (status < 0 || decrypted_size != plaintext.size() ||
        recovered != plaintext)
        return ::testing::AssertionFailure()
               << "BCryptDecrypt/roundtrip: " << status
               << ", length=" << decrypted_size;
    return ::testing::AssertionSuccess();
}

void* allocate_near(const void* entry) {
    const auto address = reinterpret_cast<uintptr_t>(entry);
    for (uintptr_t distance = 0x10000; distance < 0x10000000;
         distance += 0x10000) {
        if (address <= distance)
            break;
        auto* candidate =
            reinterpret_cast<void*>((address - distance) & ~uintptr_t{0xffff});
        if (auto* page =
                VirtualAlloc(candidate, 0x1000, MEM_RESERVE | MEM_COMMIT,
                             PAGE_EXECUTE_READWRITE))
            return page;
    }
    return nullptr;
}

// These complete x64 instruction sequences contain ONLY register/stack moves:
// property: mov [rsp+8],rbx; mov [rsp+10h],rbp
// generate: mov r11,rsp; mov [r11+8],rbx
// They have no PC-relative operands and can be copied verbatim. This is NOT an
// instruction decoder or a general relocation scheme. Any other build skips.
constexpr std::array<UCHAR, 10> property_prologue{0x48, 0x89, 0x5c, 0x24, 0x08,
                                                  0x48, 0x89, 0x6c, 0x24, 0x10};
constexpr std::array<UCHAR, 7> generate_prologue{0x4c, 0x8b, 0xdc, 0x49,
                                                 0x89, 0x5b, 0x08};

template <class Function>
struct EntryHook {
    Function& original;
    void* trampoline = nullptr;
    void* literal = nullptr;
    std::optional<blook::client::hook> installed;

    explicit EntryHook(Function& function) : original(function) {}
    EntryHook(const EntryHook&) = delete;
    EntryHook& operator=(const EntryHook&) = delete;
    ~EntryHook() {
        if (installed) {
            const auto removed = installed->remove();
            if (!removed) {
                // Never free code/literals that a still-installed hook can use.
                // Report failure and retain mappings until process exit.
                ADD_FAILURE()
                    << "Hook removal failed; retaining executable storage: "
                    << removed.error().message();
                return;
            }
        }
        original = nullptr;
        if (literal)
            VirtualFree(literal, 0, MEM_RELEASE);
        if (trampoline)
            VirtualFree(trampoline, 0, MEM_RELEASE);
    }

    template <size_t N>
    ::testing::AssertionResult arm(blook::client::session& session, void* entry,
                                   Function handler,
                                   const std::array<UCHAR, N>& expected) {
        static_assert(N >= blook::jump_patch_length);
        if (std::memcmp(entry, expected.data(), N) != 0)
            return ::testing::AssertionFailure()
                   << "Prologue changed after preflight";
        trampoline = allocate_near(entry);
        if (!trampoline)
            return ::testing::AssertionFailure()
                   << "Trampoline allocation failed: " << GetLastError();
        auto* code = static_cast<UCHAR*>(trampoline);
        std::memcpy(code, entry, N);
        // jmp qword ptr [rip+0]; absolute continuation in an unhooked
        // allocation.
        constexpr UCHAR jump[]{0xff, 0x25, 0, 0, 0, 0};
        std::memcpy(code + N, jump, sizeof(jump));
        const auto continuation = reinterpret_cast<uintptr_t>(entry) + N;
        std::memcpy(code + N + sizeof(jump), &continuation,
                    sizeof(continuation));
        if (!FlushInstructionCache(GetCurrentProcess(), code, N + 14))
            return ::testing::AssertionFailure()
                   << "FlushInstructionCache failed: " << GetLastError();
        literal = allocate_near(entry);
        if (!literal)
            return ::testing::AssertionFailure()
                   << "Literal allocation failed: " << GetLastError();
        const auto destination = reinterpret_cast<uintptr_t>(handler);
        std::memcpy(literal, &destination, sizeof(destination));
        const auto patch = blook::client::entry_jump(entry, literal);
        if (!patch)
            return ::testing::AssertionFailure()
                   << "Entry literal is out of rel32 range";
        original = reinterpret_cast<Function>(trampoline);
        auto result = session.patch(entry, *patch);
        if (!result)
            return ::testing::AssertionFailure()
                   << "session.patch: " << result.error().message();
        installed.emplace(std::move(*result));
        return ::testing::AssertionSuccess();
    }
};

TEST(ImagePage, HostBcryptCbcRoundtrip) {
    ASSERT_TRUE(cbc_roundtrip());
}

TEST(ImagePage, LiveTwoBcryptHooksOnSameImagePage) {
    char live[2]{};
    if (GetEnvironmentVariableA("BLOOK_EPT_LIVE", live, sizeof(live)) != 1 ||
        live[0] != '1')
        GTEST_SKIP()
            << "Set BLOOK_EPT_LIVE=1 to execute the live EPT regression";
    if constexpr (sizeof(void*) != 8)
        GTEST_SKIP() << "This regression requires x64 prologues";

    // bcrypt is a linked dependency: GetModuleHandle does not acquire a loader
    // reference and therefore does not require FreeLibrary.
    const auto module = GetModuleHandleW(L"bcrypt.dll");
    ASSERT_NE(module, nullptr);
    auto* property =
        reinterpret_cast<void*>(GetProcAddress(module, "BCryptSetProperty"));
    auto* generate = reinterpret_cast<void*>(
        GetProcAddress(module, "BCryptGenerateSymmetricKey"));
    ASSERT_NE(property, nullptr);
    ASSERT_NE(generate, nullptr);
    if ((reinterpret_cast<uintptr_t>(property) >> 12) !=
        (reinterpret_cast<uintptr_t>(generate) >> 12))
        GTEST_SKIP() << "This bcrypt build does not place both exports on one "
                        "4 KiB page";
    if (std::memcmp(property, property_prologue.data(),
                    property_prologue.size()) != 0 ||
        std::memcmp(generate, generate_prologue.data(),
                    generate_prologue.size()) != 0)
        GTEST_SKIP()
            << "Unsupported bcrypt prologue; no relocation is attempted";

    ASSERT_TRUE(cbc_roundtrip());
    auto opened = blook::client::session::open();
    ASSERT_TRUE(opened) << opened.error().message();
    auto& session = *opened;
    property_hits.store(0, std::memory_order_relaxed);
    generate_hits.store(0, std::memory_order_relaxed);
    {
        EntryHook<SetProperty> property_hook(original_property);
        EntryHook<GenerateKey> generate_hook(original_generate);
        ASSERT_TRUE(property_hook.arm(session, property, &property_handler,
                                      property_prologue));
        ASSERT_TRUE(generate_hook.arm(session, generate, &generate_handler,
                                      generate_prologue));
        for (int iteration = 0; iteration < 21; ++iteration) {
            SCOPED_TRACE(iteration);
            ASSERT_TRUE(cbc_roundtrip());
        }
        EXPECT_GT(property_hits.load(std::memory_order_relaxed), 0ul);
        EXPECT_GT(generate_hits.load(std::memory_order_relaxed), 0ul);
        const auto query = session.query();
        ASSERT_TRUE(query) << query.error().message();
        EXPECT_TRUE(query->running);
    }
    // Exercise the original image again after the hooks and trampoline mappings
    // have been removed; neither handler should be entered anymore.
    const auto properties_before =
        property_hits.load(std::memory_order_relaxed);
    const auto generations_before =
        generate_hits.load(std::memory_order_relaxed);
    ASSERT_TRUE(cbc_roundtrip());
    EXPECT_EQ(property_hits.load(std::memory_order_relaxed), properties_before);
    EXPECT_EQ(generate_hits.load(std::memory_order_relaxed),
              generations_before);
}

}  // namespace
