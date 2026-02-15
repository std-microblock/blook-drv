#include "pe.hpp"

namespace core {

PIMAGE_SECTION_HEADER get_section_header(uintptr_t image_base, const char* section_name) {
    if (!image_base || !section_name) {
        return nullptr;
    }
    
    auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(image_base);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return nullptr;
    }
    
    auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
        image_base + dos_header->e_lfanew);
    
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        return nullptr;
    }
    
    auto section = IMAGE_FIRST_SECTION(nt_headers);
    auto section_count = nt_headers->FileHeader.NumberOfSections;
    
    for (USHORT i = 0; i < section_count; i++) {
        if (!_strnicmp(reinterpret_cast<const char*>(section->Name),
                       section_name, IMAGE_SIZEOF_SHORT_NAME)) {
            return section;
        }
        section++;
    }
    
    return nullptr;
}

}  // namespace core
