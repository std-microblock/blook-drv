#pragma once
#ifdef _KERNEL_MODE
using uint8_t = unsigned char;
using uint16_t = unsigned short;
using uint32_t = unsigned int;
using uint64_t = unsigned long long;
using int32_t = int;
#else
#include <stdint.h>
#endif
