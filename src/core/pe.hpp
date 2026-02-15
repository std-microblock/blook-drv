#pragma once

#include <ntifs.h>
#include <ntimage.h>
#include <windef.h>

namespace core {

// PE utilities
PIMAGE_SECTION_HEADER get_section_header(uintptr_t image_base, const char* section_name);

}  // namespace core
