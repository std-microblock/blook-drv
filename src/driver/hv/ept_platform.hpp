#pragma once
#include "policy/integer.hpp"
#include <stddef.h>
#include <string.h>
#ifdef BLOOK_EPT_TEST
namespace hv { [[noreturn]] void fatal_root_error(); }
namespace hv::platform {
inline void copy(void* dst, const void* src, size_t size) { memcpy(dst, src, size); }
uint64_t physical_address(const void*);
void invalidate();
void single_step(bool);
uint64_t guest_cr3();
uint64_t translate_user(uint64_t, uint64_t);
}
#else
#include "vmx.h"
#include "translation.hpp"
namespace hv::platform {
inline void copy(void* dst, const void* src, size_t size) { __movsb(static_cast<unsigned char*>(dst), static_cast<const unsigned char*>(src), size); }
inline uint64_t physical_address(const void* p) { return MmGetPhysicalAddress(const_cast<void*>(p)).QuadPart; }
inline void invalidate() { vmx_invept(invept_all_context, {}); }
inline void single_step(bool enabled) { if (enabled) enable_monitor_trap_flag(); else disable_monitor_trap_flag(); }
inline uint64_t guest_cr3() { return vmx_vmread(VMCS_GUEST_CR3); }
inline uint64_t translate_user(uint64_t cr3, uint64_t address) { return hv::translate_user(cr3, address); }
}
#endif
