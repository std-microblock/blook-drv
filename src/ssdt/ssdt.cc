#include "ssdt/ssdt.hpp"

#include <ntimage.h>

namespace blook::ssdt {
namespace {

// A Zw* kernel stub is either a dispatcher entry that carries the service
// number as `mov eax, imm32` and jumps to the shared dispatcher (current
// builds), or a thin wrapper that jumps straight to the implementation
// (older builds). Scan linearly and take whichever shape comes first.
struct stub_info {
    uint32_t ssn{};
    void* target{};
};

stub_info analyze_stub(const void* stub) {
    const auto* code = static_cast<const uint8_t*>(stub);
    for (size_t i = 0; i < 48; ++i) {
        if (code[i] == 0xb8)  // mov eax, imm32: the service number
            return {*reinterpret_cast<const uint32_t*>(code + i + 1), nullptr};
        if (code[i] == 0xe9 || code[i] == 0xe8) {  // jmp/call rel32
            const auto disp = *reinterpret_cast<const int32_t*>(code + i + 1);
            return {0, const_cast<uint8_t*>(code + i + 5) + disp};
        }
    }
    return {};
}

bool name_equals(const char* found, const char* wanted) {
    size_t i = 0;
    while (wanted[i] && found[i] == wanted[i])
        ++i;
    return !wanted[i] && !found[i];
}

// The ntdll user-mode stub of a service carries the same service number as
// `mov eax, imm32` right after `mov r10, rcx`.
uint32_t service_number_in_image(const uint8_t* image, const char* wanted) {
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;
    const auto* nt =
        reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return 0;
    const auto& dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress)
        return 0;
    const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        image + dir.VirtualAddress);
    const auto* names =
        reinterpret_cast<const uint32_t*>(image + exports->AddressOfNames);
    const auto* ordinals = reinterpret_cast<const uint16_t*>(
        image + exports->AddressOfNameOrdinals);
    const auto* functions =
        reinterpret_cast<const uint32_t*>(image + exports->AddressOfFunctions);
    for (ULONG i = 0; i < exports->NumberOfNames; ++i) {
        const auto* found = reinterpret_cast<const char*>(image + names[i]);
        if (!name_equals(found, wanted))
            continue;
        const auto* stub = image + functions[ordinals[i]];
        if (stub[0] == 0x4c && stub[1] == 0x8b && stub[2] == 0xd1 &&
            stub[3] == 0xb8)
            return *reinterpret_cast<const uint32_t*>(stub + 4);
        return 0;
    }
    return 0;
}

uint32_t service_number_from_ntdll(const wchar_t* nt_name) {
    char wanted[64]{};
    size_t n = 0;
    for (; nt_name[n] && n < sizeof(wanted) - 1; ++n) {
        if (nt_name[n] > 0x7f)
            return 0;
        wanted[n] = static_cast<char>(nt_name[n]);
    }
    if (nt_name[n])
        return 0;

    // The 64-bit ntdll is a known-dll section: mapping it avoids parsing a
    // file off disk and works from any process context.
    UNICODE_STRING path = RTL_CONSTANT_STRING(L"\\KnownDlls\\ntdll.dll");
    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               nullptr, nullptr);
    HANDLE section{};
    if (!NT_SUCCESS(ZwOpenSection(&section, SECTION_MAP_READ, &attributes)))
        return 0;
    PVOID view = nullptr;
    SIZE_T view_size = 0;
    const auto status =
        ZwMapViewOfSection(section, ZwCurrentProcess(), &view, 0, 0, nullptr,
                           &view_size, ViewUnmap, 0, PAGE_READONLY);
    ZwClose(section);
    if (!NT_SUCCESS(status))
        return 0;
    const auto ssn =
        service_number_in_image(static_cast<const uint8_t*>(view), wanted);
    ZwUnmapViewOfSection(ZwCurrentProcess(), view);
    return ssn;
}

uint32_t service_number(const wchar_t* nt_name, void** direct) {
    *direct = nullptr;
    // The Zw* twin is exported more often than the Nt* implementation.
    wchar_t zw_name[64]{};
    zw_name[0] = L'Z';
    zw_name[1] = L'w';
    size_t n = 0;
    for (; nt_name[n + 2] && n < 61; ++n)
        zw_name[n + 2] = static_cast<wchar_t>(nt_name[n + 2]);
    UNICODE_STRING zw{};
    RtlInitUnicodeString(&zw, zw_name);
    if (auto* stub = MmGetSystemRoutineAddress(&zw)) {
        const auto info = analyze_stub(stub);
        // An old-style wrapper jumps straight to the implementation: no SSN
        // lookup needed at all.
        if (info.target)
            *direct = info.target;
        if (info.ssn && info.ssn < 0x4000)
            return info.ssn;
    }
    return service_number_from_ntdll(nt_name);
}

// The first descriptor of the service table array. KeAddSystemServiceTable
// references the array with a RIP-relative lea in its add-a-table path; the
// descriptor layout is { Base, Count, Limit, Number }, so [candidate] is the
// service table and [candidate + 0x10] the service limit.
uint64_t* service_descriptor() {
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"KeAddSystemServiceTable");
    const auto* code =
        static_cast<const uint8_t*>(MmGetSystemRoutineAddress(&name));
    if (!code)
        return nullptr;
    for (size_t i = 0; i < 0x100; ++i) {
        if (code[i] != 0x48 || code[i + 1] != 0x8d || code[i + 2] != 0x05)
            continue;  // lea rax, [rip + disp32]
        const auto disp = *reinterpret_cast<const int32_t*>(code + i + 3);
        auto* descriptor = reinterpret_cast<uint64_t*>(
            const_cast<uint8_t*>(code + i + 7) + disp);
        if (reinterpret_cast<uint64_t>(descriptor) < 0xffff000000000000ull)
            continue;
        auto* base = reinterpret_cast<uint64_t*>(descriptor[0]);
        const auto limit = *reinterpret_cast<uint32_t*>(
            reinterpret_cast<uint8_t*>(descriptor) + 0x10);
        if (reinterpret_cast<uint64_t>(base) < 0xffff000000000000ull ||
            !limit || limit > 0x4000)
            continue;
        return descriptor;
    }
    return nullptr;
}

struct service_table {
    int32_t* entries{};
    uint32_t limit{};
    bool verified{};
};

// The table pointer is boot-time constant; resolve it once, and prove the
// whole chain (SSN extraction, descriptor anchor, entry decode) against a
// service that is exported: the SSDT answer must equal the exported address.
service_table& table() {
    static service_table cached = [] {
        service_table result{};
        auto* descriptor = service_descriptor();
        if (!descriptor)
            return result;
        auto* entries =
            static_cast<int32_t*>(reinterpret_cast<void*>(descriptor[0]));
        const auto limit = *reinterpret_cast<uint32_t*>(
            reinterpret_cast<uint8_t*>(descriptor) + 0x10);
        void* direct = nullptr;
        const auto ssn = service_number(L"NtQuerySystemInformation", &direct);
        UNICODE_STRING known = RTL_CONSTANT_STRING(L"NtQuerySystemInformation");
        const auto exported = MmGetSystemRoutineAddress(&known);
        if (!ssn || ssn >= limit || !exported)
            return result;
        const auto resolved =
            reinterpret_cast<uint8_t*>(entries) + (entries[ssn] >> 4);
        if (resolved != exported)
            return result;
        result.entries = entries;
        result.limit = limit;
        result.verified = true;
        return result;
    }();
    return cached;
}
}  // namespace

void* resolve_service(const wchar_t* nt_name) {
    if (!nt_name || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return nullptr;
    UNICODE_STRING name{};
    RtlInitUnicodeString(&name, nt_name);
    if (auto* exported = MmGetSystemRoutineAddress(&name))
        return exported;
    void* direct = nullptr;
    const auto ssn = service_number(nt_name, &direct);
    if (direct)
        return direct;
    auto& services = table();
    if (!services.verified || !ssn || ssn >= services.limit)
        return nullptr;
    auto* resolved = reinterpret_cast<uint8_t*>(services.entries) +
                     (services.entries[ssn] >> 4);
    // Sanity: the routine must live in the same image as the anchor. A
    // service number that decoded to somewhere else is a wrong answer, and
    // a wrong answer must be a skipped hook, not a hook on a guess.
    UNICODE_STRING anchor_name =
        RTL_CONSTANT_STRING(L"NtQuerySystemInformation");
    const auto anchor =
        static_cast<const uint8_t*>(MmGetSystemRoutineAddress(&anchor_name));
    const auto delta =
        resolved > anchor ? resolved - anchor : anchor - resolved;
    if (!anchor || delta > 0x2000000)
        return nullptr;
    return resolved;
}
}  // namespace blook::ssdt
