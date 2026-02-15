#include "ssdt_hook.hpp"

#include "core/utils.hpp"
#include "klhk.hpp"

namespace ssdt {

// SsdtHook implementation

core::VoidResult SsdtHook::enable() {
    ASSERT_TRUE(valid_, NotInitialized);

    if (enabled_) {
        return core::ok();  // Already enabled
    }

    ASSERT_TRUE(hook_fn_, NullPointer);

    // Install the hook via manager so we receive the routine that was
    // previously in the dispatch table (this becomes this->original_ so
    // get_original() returns the function we wrap).
    void* prev = nullptr;
    ASSERT_TRUE(manager_->do_hook(index_, hook_fn_, &prev, type_), HookFailed);

    // record the routine that was previously in the table
    original_ = prev;
    enabled_ = true;
    return core::ok();
}

core::VoidResult SsdtHook::disable() {
    ASSERT_TRUE(valid_, NotInitialized);

    if (!enabled_) {
        return core::ok();  // Already disabled
    }

    // Current dispatch (may or may not point to this hook) --- if this hook
    // is the top-most (dispatch points to our hook_fn_), then restore the
    // dispatch table to `original_`. If we're a middle hook, do not touch the
    // dispatch table; instead, update downstream hooks so the chain remains
    // consistent.
    void* current = manager_->get_routine(index_, type_);

    if (current == hook_fn_) {
        // top-most hook: restore dispatch to the saved original
        ASSERT_TRUE(manager_->do_unhook(index_, original_, type_), UnhookFailed);
    } else {
        // middle/unexposed hook: we must patch any hooks that relied on our
        // function being in the chain so they now point to our `original_`.
        for (size_t i = 0; i < kMaxHooks; ++i) {
            if (&manager_->hooks_[i] == this)
                continue;

            SsdtHook& other = manager_->hooks_[i];
            if (!other.valid_)
                continue;
            if (other.index_ != index_ || other.type_ != type_)
                continue;

            // If another hook's original_ pointed to our hook function,
            // redirect it to our original_. This preserves the chain when a
            // middle hook is removed.
            if (other.original_ == hook_fn_) {
                other.original_ = original_;
            }
        }
    }

    enabled_ = false;
    return core::ok();
}

// SsdtHookManager implementation

// Global instance storage (no constructor/destructor issues in kernel mode)
alignas(SsdtHookManager) static unsigned char g_manager_storage[sizeof(
    SsdtHookManager)];
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
    ASSERT_TRUE(core::init(), NotInitialized);

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

    ASSERT_TRUE(hvm_result, HvmInitFailed);
    ASSERT_TRUE(hvm_result.value() == 0, HvmInitFailed);

    initialized_ = true;
    return core::ok();
}

unsigned int SsdtHookManager::get_ssdt_count() const {
    return klhk::get_ssdt_count();
}

unsigned int SsdtHookManager::get_shadow_ssdt_count() const {
    return klhk::get_shadow_ssdt_count();
}

core::Result<SsdtHook&> SsdtHookManager::hook_by_index(unsigned short index,
                                                       void* hook_fn,
                                                       HookType type) {
    ASSERT_TRUE(initialized_, NotInitialized);

    ASSERT_TRUE(hook_fn, NullPointer);

    // Check index validity
    if (type == HookType::Ssdt) {
        ASSERT_TRUE(index < get_ssdt_count(), InvalidSsdtIndex);
    } else {
        const auto shadow_count = get_shadow_ssdt_count();
        const auto adjusted_index = index - 0x1000;
        ASSERT_TRUE(shadow_count && adjusted_index < shadow_count, InvalidSsdtIndex);
    }

    // Find a free slot
    auto slot = find_free_slot();
    ASSERT_TRUE(slot, OutOfRange);

    // Capture the routine currently in the dispatch table so get_original()
    // for this hook returns the function we are wrapping (may be the real
    // syscall or a previously-installed hook).
    void* current = nullptr;
    if (type == HookType::Ssdt) {
        current = klhk::get_ssdt_routine(index);
    } else {
        current = klhk::get_shadow_ssdt_routine(index);
    }

    ASSERT_TRUE(current, NotFound);

    // Setup the hook (but don't enable it yet)
    slot->valid_ = true;
    slot->enabled_ = false;
    slot->index_ = index;
    slot->type_ = type;
    slot->original_ = current;  // previous dispatch
    slot->hook_fn_ = hook_fn;
    slot->manager_ = this;

    hook_count_++;

    return slot;
}

core::Result<SsdtHook&> SsdtHookManager::hook_by_syscall_name(
    const char* syscall_name, void* hook_fn, HookType type) {
    ASSERT_TRUE(syscall_name, InvalidArgument);

    auto syscall_result = [&]() {
        if (type == HookType::ShadowSsdt)
            return core::get_shadow_syscall_number(syscall_name);
        return core::get_syscall_number(syscall_name);
    }();

    if (!syscall_result) {
        return core::err(syscall_result.error());
    }

    ASSERT_TRUE(syscall_result.value() <= 0xFFFF, InvalidSsdtIndex);

    return hook_by_index(static_cast<unsigned short>(syscall_result.value()),
                         hook_fn, type);
}

// Overload that returns a hook object without setting the hook function.
// Caller is expected to assign implementation (operator<<) before enabling.
core::Result<SsdtHook&> SsdtHookManager::hook_by_syscall_name(
    const char* syscall_name, HookType type) {
    ASSERT_TRUE(syscall_name, InvalidArgument);

    auto syscall_result = [&]() {
        if (type == HookType::ShadowSsdt)
            return core::get_shadow_syscall_number(syscall_name);
        return core::get_syscall_number(syscall_name);
    }();

    if (!syscall_result) {
        return core::err(syscall_result.error());
    }

    ASSERT_TRUE(syscall_result.value() <= 0xFFFF, InvalidSsdtIndex);

    const unsigned short index =
        static_cast<unsigned short>(syscall_result.value());

    ASSERT_TRUE(initialized_, NotInitialized);

    // Check index validity
    if (type == HookType::Ssdt) {
        ASSERT_TRUE(index < get_ssdt_count(), InvalidSsdtIndex);
    } else {
        const auto shadow_count = get_shadow_ssdt_count();
        const auto adjusted_index = index - 0x1000;
        ASSERT_TRUE(shadow_count && adjusted_index < shadow_count,
                           InvalidSsdtIndex);
    }

    auto slot = find_free_slot();
    ASSERT_TRUE(slot, OutOfRange);

    void* current = nullptr;
    if (type == HookType::Ssdt) {
        current = klhk::get_ssdt_routine(index);
    } else {
        current = klhk::get_shadow_ssdt_routine(index);
    }

    ASSERT_TRUE(current, NotFound);

    // Setup the hook slot without a hook_fn_ yet
    slot->valid_ = true;
    slot->enabled_ = false;
    slot->index_ = index;
    slot->type_ = type;
    slot->original_ = current;  // previous dispatch
    slot->hook_fn_ = nullptr;
    slot->manager_ = this;

    hook_count_++;

    return core::ok(*slot);
}

bool SsdtHookManager::is_hooked(unsigned short index, HookType type) const {
    for (size_t i = 0; i < kMaxHooks; i++) {
        if (hooks_[i].valid_ && hooks_[i].index_ == index &&
            hooks_[i].type_ == type) {
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

core::Result<SsdtHook&> SsdtHookManager::find_free_slot() {
    for (size_t i = 0; i < kMaxHooks; i++) {
        if (!hooks_[i].valid_) {
            return core::ok(hooks_[i]);
        }
    }
    return core::err(core::ErrorCode::OutOfRange);
}

core::Result<SsdtHook&> SsdtHookManager::find_hook(unsigned short index,
                                                   HookType type) {
    for (size_t i = 0; i < kMaxHooks; i++) {
        if (hooks_[i].valid_ && hooks_[i].index_ == index &&
            hooks_[i].type_ == type) {
            return core::ok(hooks_[i]);
        }
    }
    return core::err(core::ErrorCode::NotFound);
}

bool SsdtHookManager::do_hook(unsigned short index, void* dest, void** original,
                              HookType type) {
    if (type == HookType::Ssdt) {
        return klhk::hook_ssdt_routine(index, dest, original);
    } else {
        return klhk::hook_shadow_ssdt_routine(index, dest, original);
    }
}

bool SsdtHookManager::do_unhook(unsigned short index, void* original,
                                HookType type) {
    if (type == HookType::Ssdt) {
        return klhk::unhook_ssdt_routine(index, original);
    } else {
        return klhk::unhook_shadow_ssdt_routine(index, original);
    }
}

}  // namespace ssdt
