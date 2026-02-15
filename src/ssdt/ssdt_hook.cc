#include "ssdt_hook.hpp"
#include "klhk.hpp"

#include "core/utils.hpp"

namespace ssdt {

//
// SsdtHook implementation
//

core::VoidResult SsdtHook::enable() {
    if (!valid_) {
        return core::err(core::ErrorCode::NotInitialized);
    }
    
    if (enabled_) {
        return core::ok();  // Already enabled
    }
    
    bool success = false;
    if (type_ == HookType::Ssdt) {
        // We already have the original, just swap in our hook
        auto dispatch = klhk::get_dispatch_array();
        if (dispatch) {
            *dispatch[index_] = hook_fn_;
            success = true;
        }
    } else {
        const auto svc_count = klhk::get_ssdt_count();
        const auto index_dispatch = (index_ - 0x1000) + svc_count;
        auto dispatch = klhk::get_dispatch_array();
        if (dispatch) {
            *dispatch[index_dispatch] = hook_fn_;
            success = true;
        }
    }
    
    if (!success) {
        return core::err(core::ErrorCode::HookFailed);
    }
    
    enabled_ = true;
    return core::ok();
}

core::VoidResult SsdtHook::disable() {
    if (!valid_) {
        return core::err(core::ErrorCode::NotInitialized);
    }
    
    if (!enabled_) {
        return core::ok();  // Already disabled
    }
    
    bool success = false;
    if (type_ == HookType::Ssdt) {
        auto dispatch = klhk::get_dispatch_array();
        if (dispatch) {
            *dispatch[index_] = original_;
            success = true;
        }
    } else {
        const auto svc_count = klhk::get_ssdt_count();
        const auto index_dispatch = (index_ - 0x1000) + svc_count;
        auto dispatch = klhk::get_dispatch_array();
        if (dispatch) {
            *dispatch[index_dispatch] = original_;
            success = true;
        }
    }
    
    if (!success) {
        return core::err(core::ErrorCode::UnhookFailed);
    }
    
    enabled_ = false;
    return core::ok();
}

//
// SsdtHookManager implementation
//

// Global instance storage (no constructor/destructor issues in kernel mode)
alignas(SsdtHookManager) static unsigned char g_manager_storage[sizeof(SsdtHookManager)];
static SsdtHookManager* g_manager_ptr = nullptr;

SsdtHookManager& SsdtHookManager::instance() {
    if (!g_manager_ptr) {
        // Placement new - manually construct in pre-allocated storage
        g_manager_ptr = reinterpret_cast<SsdtHookManager*>(g_manager_storage);
        // Zero-initialize (default construction for POD-like class)
        RtlZeroMemory(g_manager_ptr, sizeof(SsdtHookManager));
    }
    return *g_manager_ptr;
}

SsdtHookManager::~SsdtHookManager() {
    // Destructor is called manually via unhook_all()
}

core::VoidResult SsdtHookManager::initialize() {
    if (initialized_) {
        return core::ok();
    }
    
    // Initialize utils first
    if (!core::init()) {
        return core::err(core::ErrorCode::NotInitialized);
    }
    
    // Initialize klhk interface
    auto result = klhk::initialize();
    if (!result) {
        return result;
    }
    
    // Initialize HVM
    auto hvm_result = klhk::hvm_init();
    if (!hvm_result) {
        return core::err(hvm_result.error());
    }
    
    if (!NT_SUCCESS(hvm_result.value())) {
        return core::err(core::ErrorCode::HvmInitFailed);
    }
    
    initialized_ = true;
    return core::ok();
}

unsigned int SsdtHookManager::get_ssdt_count() const {
    return klhk::get_ssdt_count();
}

unsigned int SsdtHookManager::get_shadow_ssdt_count() const {
    return klhk::get_shadow_ssdt_count();
}

core::Result<SsdtHook*> SsdtHookManager::hook_by_index(
    unsigned short index,
    void* hook_fn,
    HookType type) {
    
    if (!initialized_) {
        return core::err(core::ErrorCode::NotInitialized);
    }
    
    if (!hook_fn) {
        return core::err(core::ErrorCode::NullPointer);
    }
    
    // Check index validity
    if (type == HookType::Ssdt) {
        if (index >= get_ssdt_count()) {
            return core::err(core::ErrorCode::InvalidSsdtIndex);
        }
    } else {
        const auto shadow_count = get_shadow_ssdt_count();
        const auto adjusted_index = index - 0x1000;
        if (!shadow_count || adjusted_index >= shadow_count) {
            return core::err(core::ErrorCode::InvalidSsdtIndex);
        }
    }
    
    // Check if already hooked
    if (is_hooked(index, type)) {
        return core::err(core::ErrorCode::AlreadyHooked);
    }
    
    // Find a free slot
    SsdtHook* slot = find_free_slot();
    if (!slot) {
        return core::err(core::ErrorCode::OutOfRange);
    }
    
    // Get the original function pointer
    void* original = nullptr;
    if (type == HookType::Ssdt) {
        original = klhk::get_ssdt_routine(index);
    } else {
        original = klhk::get_shadow_ssdt_routine(index);
    }
    
    if (!original) {
        return core::err(core::ErrorCode::NotFound);
    }
    
    // Setup the hook (but don't enable it yet)
    slot->valid_ = true;
    slot->enabled_ = false;
    slot->index_ = index;
    slot->type_ = type;
    slot->original_ = original;
    slot->hook_fn_ = hook_fn;
    slot->manager_ = this;
    
    hook_count_++;
    
    return slot;
}

bool SsdtHookManager::is_hooked(unsigned short index, HookType type) const {
    for (size_t i = 0; i < kMaxHooks; i++) {
        if (hooks_[i].valid_ && hooks_[i].index_ == index && hooks_[i].type_ == type) {
            return true;
        }
    }
    return false;
}

core::VoidResult SsdtHookManager::unhook_all() {
    bool any_failed = false;
    
    for (size_t i = 0; i < kMaxHooks; i++) {
        if (hooks_[i].valid_ && hooks_[i].enabled_) {
            auto result = hooks_[i].disable();
            if (!result) {
                any_failed = true;
            }
        }
        hooks_[i].valid_ = false;
        hooks_[i].enabled_ = false;
    }
    
    hook_count_ = 0;
    
    // Delay execution to ensure no thread is executing our hooks
    LARGE_INTEGER delay;
    delay.QuadPart = -10000000;  // 1 second
    KeDelayExecutionThread(KernelMode, FALSE, &delay);
    
    return any_failed ? core::err(core::ErrorCode::UnhookFailed) : core::ok();
}

void* SsdtHookManager::get_routine(unsigned short index, HookType type) const {
    if (type == HookType::Ssdt) {
        return klhk::get_ssdt_routine(index);
    } else {
        return klhk::get_shadow_ssdt_routine(index);
    }
}

SsdtHook* SsdtHookManager::find_free_slot() {
    for (size_t i = 0; i < kMaxHooks; i++) {
        if (!hooks_[i].valid_) {
            return &hooks_[i];
        }
    }
    return nullptr;
}

SsdtHook* SsdtHookManager::find_hook(unsigned short index, HookType type) {
    for (size_t i = 0; i < kMaxHooks; i++) {
        if (hooks_[i].valid_ && hooks_[i].index_ == index && hooks_[i].type_ == type) {
            return &hooks_[i];
        }
    }
    return nullptr;
}

bool SsdtHookManager::do_hook(unsigned short index, void* dest, void** original, HookType type) {
    if (type == HookType::Ssdt) {
        return klhk::hook_ssdt_routine(index, dest, original);
    } else {
        return klhk::hook_shadow_ssdt_routine(index, dest, original);
    }
}

bool SsdtHookManager::do_unhook(unsigned short index, void* original, HookType type) {
    if (type == HookType::Ssdt) {
        return klhk::unhook_ssdt_routine(index, original);
    } else {
        return klhk::unhook_shadow_ssdt_routine(index, original);
    }
}

}  // namespace ssdt
