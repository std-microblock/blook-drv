#include "utils.hpp"

#include "pe.hpp"

namespace core {

// Helper: convert hex char to byte
static unsigned char hex_char_to_byte(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return 0;
}

// Helper: parse hex pattern string into bytes and wildcards
// Returns false if pattern is invalid
static bool parse_hex_pattern(const char* hex_pattern, unsigned char* bytes,
                              bool* wildcards, size_t* out_len) {
    size_t len = 0;
    const char* p = hex_pattern;

    while (*p) {
        // Skip whitespace
        if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
            p++;
            continue;
        }

        // Check for wildcard
        if (p[0] == '?' && p[1] == '?') {
            wildcards[len] = true;
            bytes[len] = 0;
            len++;
            p += 2;
        } else if ((p[0] >= '0' && p[0] <= '9') ||
                   (p[0] >= 'A' && p[0] <= 'F') ||
                   (p[0] >= 'a' && p[0] <= 'f')) {
            // Must have two hex digits
            if (!p[1] || (!((p[1] >= '0' && p[1] <= '9') ||
                            (p[1] >= 'A' && p[1] <= 'F') ||
                            (p[1] >= 'a' && p[1] <= 'f')))) {
                return false;
            }

            wildcards[len] = false;
            bytes[len] = (hex_char_to_byte(p[0]) << 4) | hex_char_to_byte(p[1]);
            len++;
            p += 2;
        } else {
            return false;
        }
    }

    *out_len = len;
    return len > 0;
}

// Pattern matching implementation
uintptr_t find_pattern(uintptr_t base, size_t size, const char* hex_pattern) {
    if (!base || !size || !hex_pattern) {
        return 0;
    }

    // Parse pattern (max 256 bytes)
    unsigned char pattern_bytes[256];
    bool pattern_wildcards[256];
    size_t pattern_len = 0;

    if (!parse_hex_pattern(hex_pattern, pattern_bytes, pattern_wildcards,
                           &pattern_len)) {
        return 0;
    }

    // Search for pattern
    for (size_t i = 0; i <= size - pattern_len; i++) {
        bool match = true;
        const unsigned char* data =
            reinterpret_cast<const unsigned char*>(base + i);

        for (size_t j = 0; j < pattern_len; j++) {
            if (!pattern_wildcards[j] && data[j] != pattern_bytes[j]) {
                match = false;
                break;
            }
        }

        if (match) {
            return base + i;
        }
    }

    return 0;
}

uintptr_t find_pattern_section(uintptr_t base, const char* section_name,
                               const char* hex_pattern) {
    if (!base || !section_name || !hex_pattern) {
        return 0;
    }

    auto* section = get_section_header(base, section_name);
    if (!section) {
        return 0;
    }

    return find_pattern(base + section->VirtualAddress, section->SizeOfRawData,
                        hex_pattern);
}

uintptr_t find_pattern_km(const wchar_t* module_name, const char* section_name,
                          const char* hex_pattern) {
    if (!module_name || !section_name || !hex_pattern) {
        return 0;
    }

    uintptr_t module_base = get_kernel_module_base(module_name);
    if (!module_base) {
        return 0;
    }

    return find_pattern_section(module_base, section_name, hex_pattern);
}

void* get_system_routine(const wchar_t* routine_name) {
    if (!routine_name) {
        return nullptr;
    }

    UNICODE_STRING routine{};
    RtlInitUnicodeString(&routine, routine_name);

    return MmGetSystemRoutineAddress(&routine);
}

uintptr_t get_ntos_base() {
    using f_RtlPcToFileHeader = PVOID (*)(PVOID PcValue, PVOID* BaseOfImage);
    auto RtlPcToFileHeader = reinterpret_cast<f_RtlPcToFileHeader>(
        get_system_routine(L"RtlPcToFileHeader"));

    if (!RtlPcToFileHeader) {
        return 0;
    }

    uintptr_t ntos_base = 0;
    RtlPcToFileHeader(RtlPcToFileHeader, reinterpret_cast<void**>(&ntos_base));

    return ntos_base;
}

bool init() {
    uintptr_t ntos_base = get_ntos_base();

    if (!ntos_base) {
        return false;
    }

    PsLoadedModuleList = reinterpret_cast<PLIST_ENTRY>(
        get_system_routine(L"PsLoadedModuleList"));

    if (!PsLoadedModuleList) {
        auto result = find_pattern_section(ntos_base, ".text",
                                           "C743??????????488943184889");

        if (!result) {
            return false;
        }

        result += 0xB;
        PsLoadedModuleList = reinterpret_cast<PLIST_ENTRY>(
            result + *reinterpret_cast<int*>(result + 0x3) + 0x7);
    }

    PsLoadedModuleResource = reinterpret_cast<PERESOURCE>(
        get_system_routine(L"PsLoadedModuleResource"));

    if (!PsLoadedModuleResource) {
        auto result = find_pattern_section(ntos_base, ".text", "4123FF66");

        if (!result) {
            return false;
        }

        result += 0xA;
        PsLoadedModuleResource = reinterpret_cast<PERESOURCE>(
            result + *reinterpret_cast<int*>(result + 0x3) + 0x7);
    }

    return PsLoadedModuleList && PsLoadedModuleResource;
}

uintptr_t get_kernel_module_base(const wchar_t* module_name) {
    if (!module_name || !PsLoadedModuleList || !PsLoadedModuleResource) {
        return 0;
    }

    UNICODE_STRING module{};
    RtlInitUnicodeString(&module, module_name);

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(PsLoadedModuleResource, TRUE);

    uintptr_t module_base = 0;

    for (auto* entry = PsLoadedModuleList->Flink; entry != PsLoadedModuleList;
         entry = entry->Flink) {
        auto* ldr_entry =
            CONTAINING_RECORD(entry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (!RtlCompareUnicodeString(&ldr_entry->BaseDllName, &module, TRUE)) {
            module_base = reinterpret_cast<uintptr_t>(ldr_entry->DllBase);
            break;
        }
    }

    ExReleaseResourceLite(PsLoadedModuleResource);
    KeLeaveCriticalRegion();

    return module_base;
}

}  // namespace core
