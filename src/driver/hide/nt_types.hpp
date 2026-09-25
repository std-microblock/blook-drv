#pragma once
#include <ntifs.h>

// This Windows Driver Kit no longer ships SYSTEM_INFORMATION_CLASS,
// SYSTEM_PROCESS_INFORMATION or RTL_PROCESS_MODULES, so the structures the
// handlers walk are declared here.
//
// Only the fields that are actually read are described, and every read is
// bounds checked against the length the service returned. The leading members
// of SYSTEM_PROCESS_INFORMATION have been stable since Vista; the two fields
// used below (ImageName, UniqueProcessId) sit at fixed offsets behind them.
namespace blook::hide {

enum class system_information_class : ULONG {
    process = 5,
    module = 11,
    kernel_debugger = 35,
};

struct system_process_entry {
    ULONG next_entry_offset;
    ULONG number_of_threads;
    LARGE_INTEGER working_set_private_size;
    ULONG hard_fault_count;
    ULONG number_of_threads_high_watermark;
    ULONGLONG cycle_time;
    LARGE_INTEGER create_time;
    LARGE_INTEGER user_time;
    LARGE_INTEGER kernel_time;
    UNICODE_STRING image_name;
    ULONG base_priority;
    HANDLE unique_process_id;
};

struct rtl_process_module_information {
    PVOID section;
    PVOID mapped_base;
    PVOID image_base;
    ULONG image_size;
    ULONG flags;
    USHORT load_order_index;
    USHORT init_order_index;
    USHORT load_count;
    USHORT offset_to_file_name;
    UCHAR full_path_name[256];
};

struct rtl_process_modules {
    ULONG number_of_modules;
    rtl_process_module_information modules[1];
};

struct system_kernel_debugger_information {
    BOOLEAN enabled;
    BOOLEAN not_present;
};

static_assert(sizeof(rtl_process_module_information) == 0x128);
static_assert(sizeof(system_process_entry) == 0x58);
}  // namespace blook::hide
