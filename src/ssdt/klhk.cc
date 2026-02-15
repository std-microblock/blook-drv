#include "klhk.hpp"

#include "Veil.h"
#include "core/utils.hpp"

//
// Global pointers for klhk.sys variables
//
namespace {

PETHREAD* g_hvm_thread_object = nullptr;
PLONG g_hvm_run_requests = nullptr;
PRKEVENT g_hvm_notification_event = nullptr;
PRKEVENT g_hvm_sync_event = nullptr;
PNTSTATUS g_hvm_status = nullptr;
void*** g_system_dispatch_array = nullptr;
unsigned int* g_ssdt_service_count = nullptr;
unsigned int* g_shadow_ssdt_service_count = nullptr;
unsigned int* g_provider = nullptr;
bool g_initialized = false;

}  // namespace

bool ssdt::klhk::is_loaded() {
    return core::get_kernel_module_base(L"klhk.sys") != 0;
}

core::VoidResult ssdt::klhk::initialize() {
    if (g_initialized) {
        return core::ok();
    }

    if (!is_loaded()) {
        return core::err(core::ErrorCode::KlhkNotLoaded);
    }

    //
    // Find klhk's hvm thread object
    //
    auto presult =
        core::find_pattern_km(L"klhk.sys", ".text", "48392D????????89");

    ASSERT_TRUE_ERR(presult, KlhkInitFailed);

    g_hvm_thread_object = reinterpret_cast<PETHREAD*>(
        presult + *reinterpret_cast<int*>(presult + 0x3) + 0x7);

    //
    // Find klhk's hvm run counter
    //
    presult =
        core::find_pattern_km(L"klhk.sys", ".text", "F0FF05????????488D0D");

    ASSERT_TRUE_ERR(presult, KlhkInitFailed);

    g_hvm_run_requests = reinterpret_cast<PLONG>(
        presult + *reinterpret_cast<int*>(presult + 0x3) + 0x7);

    //
    // Find klhk's hvm notification event
    //
    presult += 0x7;
    g_hvm_notification_event = reinterpret_cast<PRKEVENT>(
        presult + *reinterpret_cast<int*>(presult + 0x3) + 0x7);

    //
    // Find klhk's hvm synchronization event
    //
    presult =
        core::find_pattern_km(L"klhk.sys", ".text", "488D05????????498973");

    ASSERT_TRUE_ERR(presult, KlhkInitFailed);

    g_hvm_sync_event = reinterpret_cast<PRKEVENT>(
        presult + *reinterpret_cast<int*>(presult + 0x3) + 0x7);

    //
    // Find klhk's hvm status
    //
    presult = core::find_pattern_km(L"klhk.sys", ".text", "8B1D????????89");

    ASSERT_TRUE_ERR(presult, KlhkInitFailed);

    g_hvm_status = reinterpret_cast<PNTSTATUS>(
        presult + *reinterpret_cast<int*>(presult + 0x2) + 0x6);

    //
    // Find klhk's service table
    //
    presult =
        core::find_pattern_km(L"klhk.sys", "_hvmcode", "4C8D0D????????4D");

    ASSERT_TRUE_ERR(presult, KlhkInitFailed);

    g_system_dispatch_array = reinterpret_cast<void***>(
        presult + *reinterpret_cast<int*>(presult + 0x3) + 0x7);

    //
    // Find number of services (SSDT)
    //
    presult = core::find_pattern_km(L"klhk.sys", ".text", "890D????????8BD3");

    ASSERT_TRUE_ERR(presult, KlhkInitFailed);

    g_ssdt_service_count = reinterpret_cast<unsigned int*>(
        presult + *reinterpret_cast<int*>(presult + 0x2) + 0x6);

    //
    // Find number of services (Shadow SSDT)
    //
    presult = core::find_pattern_km(L"klhk.sys", ".text", "8905????????85C0");

    ASSERT_TRUE_ERR(presult, KlhkInitFailed);

    g_shadow_ssdt_service_count = reinterpret_cast<unsigned int*>(
        presult + *reinterpret_cast<int*>(presult + 0x2) + 0x6);

    //
    // Find provider data
    //
    presult = core::find_pattern_km(L"klhk.sys", ".text", "391D????????75");

    ASSERT_TRUE_ERR(presult, KlhkInitFailed);

    g_provider = reinterpret_cast<unsigned int*>(
        presult + *reinterpret_cast<int*>(presult + 2) + 0x6);

    g_initialized = true;
    return core::ok();
}

core::Result<NTSTATUS> ssdt::klhk::hvm_init() {
    if (!g_initialized) {
        return core::err(core::ErrorCode::NotInitialized);
    }

    if (!g_hvm_thread_object || !*g_hvm_thread_object) {
        return core::err(core::ErrorCode::HvmInitFailed);
    }
    if (!g_hvm_run_requests) {
        return core::err(core::ErrorCode::HvmInitFailed);
    }
    if (!g_hvm_notification_event) {
        return core::err(core::ErrorCode::HvmInitFailed);
    }
    if (!g_hvm_sync_event) {
        return core::err(core::ErrorCode::HvmInitFailed);
    }
    if (!g_hvm_status) {
        return core::err(core::ErrorCode::HvmInitFailed);
    }
    if (!g_provider) {
        return core::err(core::ErrorCode::HvmInitFailed);
    }

    //
    // Set provider to random value
    //
    *g_provider = 4;

    //
    // Hypervisor initialization
    //
    _InterlockedIncrement(g_hvm_run_requests);
    KeResetEvent(g_hvm_notification_event);
    KeSetEvent(g_hvm_sync_event, IO_NO_INCREMENT, FALSE);
    KeWaitForSingleObject(g_hvm_notification_event, Executive, KernelMode,
                          FALSE, nullptr);

    //
    // Return status
    //
    return *g_hvm_status;
}

unsigned int ssdt::klhk::get_ssdt_count() {
    return g_ssdt_service_count ? *g_ssdt_service_count : 0;
}

unsigned int ssdt::klhk::get_shadow_ssdt_count() {
    return g_shadow_ssdt_service_count ? *g_shadow_ssdt_service_count : 0;
}

void*** ssdt::klhk::get_dispatch_array() {
    return g_system_dispatch_array;
}

bool ssdt::klhk::hook_ssdt_routine(unsigned short index, void* dest,
                                   void** original) {
    if (!g_system_dispatch_array || !dest || !original) {
        return false;
    }

    const auto svc_count = get_ssdt_count();
    if (!svc_count || index >= svc_count) {
        return false;
    }

    *original = *g_system_dispatch_array[index];
    *g_system_dispatch_array[index] = dest;
    return true;
}

bool ssdt::klhk::unhook_ssdt_routine(unsigned short index, void* original) {
    if (!g_system_dispatch_array || !original) {
        return false;
    }

    const auto svc_count = get_ssdt_count();
    if (!svc_count || index >= svc_count ||
        *g_system_dispatch_array[index] == original) {
        return false;
    }

    *g_system_dispatch_array[index] = original;
    return true;
}

bool ssdt::klhk::hook_shadow_ssdt_routine(unsigned short index, void* dest,
                                          void** original) {
    if (!g_system_dispatch_array || !dest || !original) {
        return false;
    }

    const auto svc_count = get_ssdt_count();
    const auto svc_count_shadow = get_shadow_ssdt_count();

    if (!svc_count || !svc_count_shadow) {
        return false;
    }

    const auto index_dispatch = (index - 0x1000) + svc_count;
    const auto limit = svc_count + svc_count_shadow;

    if (index_dispatch >= limit) {
        return false;
    }

    *original = *g_system_dispatch_array[index_dispatch];
    *g_system_dispatch_array[index_dispatch] = dest;
    return true;
}

bool ssdt::klhk::unhook_shadow_ssdt_routine(unsigned short index,
                                            void* original) {
    if (!g_system_dispatch_array || !original) {
        return false;
    }

    const auto svc_count = get_ssdt_count();
    const auto svc_count_shadow = get_shadow_ssdt_count();

    if (!svc_count || !svc_count_shadow) {
        return false;
    }

    const auto index_dispatch = (index - 0x1000) + svc_count;
    const auto limit = svc_count + svc_count_shadow;

    if (index_dispatch >= limit ||
        *g_system_dispatch_array[index_dispatch] == original) {
        return false;
    }

    *g_system_dispatch_array[index_dispatch] = original;
    return true;
}

void* ssdt::klhk::get_ssdt_routine(unsigned short index) {
    if (!g_system_dispatch_array) {
        return nullptr;
    }

    const auto svc_count = get_ssdt_count();
    return (svc_count && index < svc_count) ? *g_system_dispatch_array[index]
                                            : nullptr;
}

void* ssdt::klhk::get_shadow_ssdt_routine(unsigned short index) {
    if (!g_system_dispatch_array) {
        return nullptr;
    }

    const auto svc_count = get_ssdt_count();
    const auto svc_count_shadow = get_shadow_ssdt_count();

    if (!svc_count || !svc_count_shadow) {
        return nullptr;
    }

    const auto index_dispatch = (index - 0x1000) + svc_count;
    const auto limit = svc_count + svc_count_shadow;

    return (index_dispatch < limit) ? *g_system_dispatch_array[index_dispatch]
                                    : nullptr;
}
