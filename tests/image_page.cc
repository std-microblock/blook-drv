// Minimal repro of the crash seen in the game: two EPT entry hooks on the SAME
// 4 KiB *image* page (bcrypt.dll: BCryptSetProperty @0x4ad0 and
// BCryptGenerateSymmetricKey @0x4d50 both live in page 0x4xxx), then exercise
// both functions and check that they still behave exactly as before.
#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstring>
#include <memory>
#include <cstdint>
#include <vector>

#include "client/ept.hpp"

static int g_bad = 0;
static long g_hits_prop = 0, g_hits_gen = 0;

typedef long(__cdecl *fn4)(void *, void *, uint64_t, uint64_t);

static void *alloc_near(void *t) {
    uintptr_t a = (uintptr_t)t;
    for (uintptr_t d = 0x10000; d < 0x10000000ull; d += 0x10000) {
        if (a <= d) break;
        void *p = VirtualAlloc((void *)((a - d) & ~(uintptr_t)0xFFFF), 0x1000,
                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (p) return p;
    }
    return nullptr;
}
static uint8_t *build_stub(uint8_t *entry, size_t covered) {
    uint8_t *page = (uint8_t *)alloc_near(entry);
    if (!page) return nullptr;
    memcpy(page, entry, covered);
    for (size_t i = 0; i + 5 <= covered;) {
        if (page[i] != 0xE8 && page[i] != 0xE9) { ++i; continue; }
        int32_t rel; memcpy(&rel, page + i + 1, 4);
        const uint8_t *tgt = entry + i + 5 + rel;
        int64_t n = (int64_t)(tgt - (page + i + 5));
        if (n < 0x7ffffff0ll && n > -0x7ffffff0ll) { int32_t v = (int32_t)n; memcpy(page + i + 1, &v, 4); }
        i += 5;
    }
    uint8_t *j = page + covered;
    uint64_t *lit = (uint64_t *)(j + 6);
    *lit = (uint64_t)(entry + covered);
    int64_t rel = (int64_t)((uint8_t *)lit - (j + 6));
    j[0] = 0xFF; j[1] = 0x25; memcpy(j + 2, &rel, 4);
    FlushInstructionCache(GetCurrentProcess(), page, covered + 14);
    return page;
}
static fn4 g_orig_prop = nullptr, g_orig_gen = nullptr;
static std::vector<std::unique_ptr<blook::client::hook>> g_keep;

extern "C" __declspec(dllexport) uint64_t __cdecl hProp(void *a, void *b, uint64_t c, uint64_t d) {
    ++g_hits_prop;
    return g_orig_prop(a, b, c, d);
}
extern "C" __declspec(dllexport) uint64_t __cdecl hGen(void *a, void *b, uint64_t c, uint64_t d) {
    ++g_hits_gen;
    return g_orig_gen(a, b, c, d);
}

static bool arm(blook::client::session &sess, void *entry, void *handler, const uint8_t *expect, size_t covered, fn4 *orig) {
    if (memcmp(entry, expect, covered) != 0) { printf("  prologue mismatch at %p\n", entry); return false; }
    uint8_t *stub = build_stub((uint8_t *)entry, covered);
    if (!stub) { printf("  stub build failed\n"); return false; }
    *orig = (fn4)stub;
    void *literal = alloc_near(entry);
    *(uint64_t *)literal = (uint64_t)handler;
    auto bytes = blook::client::entry_jump(entry, literal);
    if (!bytes) { printf("  entry_jump failed\n"); return false; }
    auto h = sess.patch(entry, *bytes);
    if (!h) { printf("  patch FAILED %lu\n", h.error().value()); return false; }
    g_keep.push_back(std::make_unique<blook::client::hook>(std::move(*h)));
    return true;
}

static int cbc_roundtrip(const char *tag) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0) { printf("  [%s] open alg failed\n", tag); return 1; }
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                      (ULONG)((wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) * sizeof(wchar_t)), 0);
    unsigned char obj[512]; BCRYPT_KEY_HANDLE key = nullptr;
    unsigned char secret[16]; for (int i = 0; i < 16; ++i) secret[i] = (unsigned char)(0xA0 + i);
    if (BCryptGenerateSymmetricKey(alg, &key, obj, sizeof obj, secret, sizeof secret, 0) < 0) { printf("  [%s] genkey failed\n", tag); return 1; }
    unsigned char iv[16], pt[32]{}, ct[64]{}, back[64]{};
    for (int i = 0; i < 16; ++i) iv[i] = (unsigned char)(0x10 + i);
    for (int i = 0; i < 32; ++i) pt[i] = (unsigned char)(i * 3 + 1);
    ULONG g1 = 0, g2 = 0;
    long e = BCryptEncrypt(key, pt, sizeof pt, nullptr, iv, sizeof iv, ct, sizeof ct, &g1, 0);
    long d = BCryptDecrypt(key, ct, g1, nullptr, iv, sizeof iv, back, sizeof back, &g2, 0);
    const bool ok = e >= 0 && d >= 0 && g2 == sizeof pt && memcmp(back, pt, sizeof pt) == 0;
    printf("  [%s] enc=0x%lx dec=0x%lx outLen=%lu %s\n", tag, (unsigned long)e, (unsigned long)d, g2, ok ? "MATCH" : "*** MISMATCH ***");
    BCryptDestroyKey(key); BCryptCloseAlgorithmProvider(alg, 0);
    return ok ? 0 : 1;
}

int main() {
    auto opened = blook::client::session::open();
    if (!opened) { printf("session::open failed %lu\n", opened.error().value()); return 1; }
    auto &sess = *opened;

    HMODULE bcrypt = LoadLibraryW(L"bcrypt.dll");
    if (!bcrypt) { printf("bcrypt.dll load failed\n"); return 1; }
    void *pProp = (void *)GetProcAddress(bcrypt, "BCryptSetProperty");
    void *pGen = (void *)GetProcAddress(bcrypt, "BCryptGenerateSymmetricKey");
    printf("BCryptSetProperty=%p BCryptGenerateSymmetricKey=%p same_page=%s\n", pProp, pGen,
           ((uintptr_t)pProp >> 12) == ((uintptr_t)pGen >> 12) ? "YES" : "NO");
    if (((uintptr_t)pProp >> 12) != ((uintptr_t)pGen >> 12)) { printf("probe invalid: not on one page\n"); return 2; }

    printf("-- baseline round trip\n");
    if (cbc_roundtrip("baseline")) g_bad++;

    static const uint8_t kProp[10] = {0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x6c, 0x24, 0x10};
    static const uint8_t kGen[7] = {0x4c, 0x8b, 0xdc, 0x49, 0x89, 0x5b, 0x08};
    printf("-- arming two hooks in the SAME image page\n");
    if (!arm(sess, pProp, (void *)&hProp, kProp, sizeof kProp, &g_orig_prop)) g_bad++;
    if (!arm(sess, pGen, (void *)&hGen, kGen, sizeof kGen, &g_orig_gen)) g_bad++;

    printf("-- round trip with both hooks installed\n");
    if (cbc_roundtrip("hooked")) g_bad++;
    for (int i = 0; i < 20; ++i) if (cbc_roundtrip("loop")) g_bad++;
    printf("  hits: SetProperty=%ld GenerateSymmetricKey=%ld (want >0 both)\n", g_hits_prop, g_hits_gen);
    if (!g_hits_prop || !g_hits_gen) g_bad++;

    auto q = sess.query();
    printf("query running=%u hooks=%u\n", q ? q->running : 0, q ? q->hooks : 0);
    printf("RESULT bad=%d\n", g_bad);
    return g_bad;
}