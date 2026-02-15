#pragma once

#include <ntifs.h>
#include <windef.h>

#include "core/core.hpp"
#include "core/expected.hpp"

namespace ssdt {

// Maximum number of concurrent hooks supported
constexpr size_t kMaxHooks = 64;

// Hook type enumeration
enum class HookType {
    Ssdt,       // Regular SSDT
    ShadowSsdt  // Shadow SSDT (win32k)
};

// Forward declaration
class SsdtHookManager;

// Represents a single SSDT hook
// Provides methods to enable/disable the hook and call the original function
class SsdtHook {
    friend class SsdtHookManager;

public:
    SsdtHook() = default;
    
    // Check if this hook object is valid
    [[nodiscard]] bool is_valid() const { return valid_; }
    
    // Check if hook is currently enabled
    [[nodiscard]] bool is_enabled() const { return enabled_; }
    
    // Get the SSDT index
    [[nodiscard]] unsigned short index() const { return index_; }
    
    // Get hook type
    [[nodiscard]] HookType type() const { return type_; }
    
    // Enable the hook (install it into SSDT)
    [[nodiscard]] core::VoidResult enable();
    
    // Disable the hook (restore original entry)
    [[nodiscard]] core::VoidResult disable();
    
    // Get pointer to original function
    template <typename T>
    [[nodiscard]] T get_original() const {
        return reinterpret_cast<T>(original_);
    }

    template <auto Fn>
    [[nodiscard]] auto get_original() const {
        return reinterpret_cast<decltype(Fn)>(original_);
    }

    // Assign a non-capturing lambda / function pointer as the hook implementation.
    // Example: hook << [](Args...){ /* ... */ };
    template <typename Fn>
    SsdtHook& operator<<(Fn fn) {
        // requires non-capturing lambda or function pointer (convertible to function pointer)
        hook_fn_ = reinterpret_cast<void*>(+fn);
        return *this;
    }
    
private:
    bool valid_ = false;
    bool enabled_ = false;
    unsigned short index_ = 0;
    HookType type_ = HookType::Ssdt;
    void* original_ = nullptr;
    void* hook_fn_ = nullptr;
    SsdtHookManager* manager_ = nullptr;
};

// Manages SSDT hooks through Kaspersky's klhk.sys
// Singleton-style manager that handles all hook operations
class SsdtHookManager {
    friend class SsdtHook;

public:
    // Get singleton instance
    static SsdtHookManager& instance();
    
    // Initialize the manager (must be called before using hooks)
    [[nodiscard]] core::VoidResult initialize();
    
    // Check if manager is initialized
    [[nodiscard]] bool is_initialized() const { return initialized_; }
    
    // Get SSDT service count
    [[nodiscard]] unsigned int get_ssdt_count() const;
    
    // Get Shadow SSDT service count
    [[nodiscard]] unsigned int get_shadow_ssdt_count() const;
    
        // Hook installation methods
        
    // Hook by index (returns a disabled hook that must be enabled)
    [[nodiscard]] core::Result<SsdtHook&> hook_by_index(
        unsigned short index,
        void* hook_fn,
        HookType type = HookType::Ssdt);

    // Hook by syscall name (returns a disabled hook that must be enabled)
    [[nodiscard]] core::Result<SsdtHook&> hook_by_syscall_name(
        const char* syscall_name,
        void* hook_fn,
        HookType type = HookType::Ssdt);

    // Hook by syscall name (returns a disabled hook *without* a hook fn set).
    // Use `hook_obj << [](...) { ... };` to assign the handler, then call
    // `hook_obj->enable()`.
    [[nodiscard]] core::Result<SsdtHook&> hook_by_syscall_name(
        const char* syscall_name,
        HookType type = HookType::Ssdt);
    
    // Check if an index is already hooked
    [[nodiscard]] bool is_hooked(unsigned short index, HookType type = HookType::Ssdt) const;
    
    // Unhook all installed hooks
    [[nodiscard]] core::VoidResult unhook_all();
    
    // Get a routine's current address
    [[nodiscard]] void* get_routine(unsigned short index, HookType type = HookType::Ssdt) const;
    
private:
    SsdtHookManager() = default;
    ~SsdtHookManager();
    
    // Non-copyable
    SsdtHookManager(const SsdtHookManager&) = delete;
    SsdtHookManager& operator=(const SsdtHookManager&) = delete;
    
    // Internal hook/unhook operations
    [[nodiscard]] bool do_hook(unsigned short index, void* dest, void** original, HookType type);
    [[nodiscard]] bool do_unhook(unsigned short index, void* original, HookType type);
    
    // Find a free hook slot
    [[nodiscard]] core::Result<SsdtHook&> find_free_slot();
    
    // Find hook by index
    [[nodiscard]] core::Result<SsdtHook&> find_hook(unsigned short index, HookType type);
    
    bool initialized_ = false;
    SsdtHook hooks_[kMaxHooks] = {};
    size_t hook_count_ = 0;
};

}  // namespace ssdt
