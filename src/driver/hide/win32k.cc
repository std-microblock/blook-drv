// win32k window hiding.
//
// The previous implementation hooked the shadow SSDT through a vulnerable
// driver. Everything needed is exported by the loaded modules instead:
// win32kfull.sys exports the NtUser* service implementations by name, and
// win32k.sys exports W32pServiceTable / W32pServiceLimit. Resolving by name
// keeps this build independent - no syscall numbers, no table layouts.
//
// Disassembly of the exports confirms the plain Microsoft x64 convention with
// the documented argument order (NtUserQueryWindow reads its window handle from
// rcx and its index from edx, NtUserFindWindowEx reads arguments three and four
// from r8 and r9) and no hidden trailing argument, so the handlers below can
// use the documented signatures.
#include "win32k.hpp"

#include <ntifs.h>

#include <ntimage.h>

#include "driver/hooks.hpp"
#include "driver/hide/nt_types.hpp"
#include "driver/hide/roles.hpp"

namespace blook::hide::win32k {
namespace {
constexpr ULONG module_information_class = 11;

// POINT is a user-mode type; a kernel build has to describe it itself. Two
// LONGs are passed exactly like the user-mode structure: in one register.
struct point {
    LONG x;
    LONG y;
};

using zw_query_system_information_t = NTSTATUS(*)(ULONG, PVOID, ULONG, PULONG);
using query_window_t = ULONG_PTR(*)(void* window, ULONG index);
using find_window_ex_t = void* (*)(void* parent, void* after, void* class_name, void* window_name, ULONG type);
using build_hwnd_list_t = NTSTATUS(*)(void* desktop, void* next, BOOLEAN children, BOOLEAN immersive,
                                      ULONG thread_id, ULONG count, void** list, PULONG returned);
using get_foreground_window_t = void* (*)();
using window_from_point_t = void* (*)(point value);

inline constexpr ULONG window_process_index = 0;

struct service {
    uint64_t id{};
    // Where the resolved entry point lives, and the pointer the install loop
    // publishes through (`*original = ...`). Every service has to point at its
    // own storage - the nt profile builds the same pair by hand in its entry
    // table - otherwise the very first install writes through a null pointer.
    void* resolved{};
    void** original{&resolved};
};

service query_window;
service find_window_ex;
service build_hwnd_list;
service get_foreground_window;
service window_from_point;

void* win32kfull_base{};
uint64_t win32kfull_size{};
void* last_foreground{};

class window final {
    uint64_t id_;

public:
    explicit window(uint64_t id) : id_(id) { if (id_ && !begin_hook_window(id_)) id_ = 0; }
    // Only an open window makes the hooked page run the untouched bytes; the
    // callers below check this before invoking the original.
    explicit operator bool() const { return id_ != 0; }
    ~window() { if (id_) end_hook_window(id_); }
    window(const window&) = delete;
    window& operator=(const window&) = delete;
};

zw_query_system_information_t zw_query_system_information() {
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"ZwQuerySystemInformation");
    return reinterpret_cast<zw_query_system_information_t>(MmGetSystemRoutineAddress(&name));
}

// Locate a loaded module through the system module list. Uses the ntoskrnl
// routine directly so it also works before the nt hooks are installed.
struct module_range {
    void* base{};
    uint64_t size{};
};

module_range find_module(const char* wanted) {
    module_range result;
    auto query = zw_query_system_information();
    if (!query) return result;
    ULONG needed{};
    query(module_information_class, nullptr, 0, &needed);
    if (!needed || needed > (16u << 20)) return result;
    auto* buffer = static_cast<uint8_t*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, needed, 'kwbl'));
    if (!buffer) return result;
    if (NT_SUCCESS(query(module_information_class, buffer, needed, &needed))) {
        auto* modules = reinterpret_cast<rtl_process_modules*>(buffer);
        for (ULONG i = 0; i < modules->number_of_modules; ++i) {
            const auto& entry = modules->modules[i];
            const auto* path = reinterpret_cast<const char*>(entry.full_path_name);
            size_t length = 0;
            while (length < 256 && path[length]) ++length;
            if (!contains(path, length, wanted)) continue;
            result.base = entry.image_base;
            result.size = entry.image_size;
            break;
        }
    }
    ExFreePoolWithTag(buffer, 'kwbl');
    return result;
}

// Minimal PE export lookup. Every read is guarded: a module whose headers are
// not resident must never turn into a fault in root context.
void* find_export(void* base, const char* wanted, uint64_t image_size) {
    if (!base || !image_size) return nullptr;
    auto* bytes = static_cast<uint8_t*>(base);
    __try {
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(bytes + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return nullptr;
        const auto& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!directory.VirtualAddress || directory.Size > image_size) return nullptr;
        const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(bytes + directory.VirtualAddress);
        const auto* names = reinterpret_cast<const ULONG*>(bytes + exports->AddressOfNames);
        const auto* ordinals = reinterpret_cast<const USHORT*>(bytes + exports->AddressOfNameOrdinals);
        const auto* functions = reinterpret_cast<const ULONG*>(bytes + exports->AddressOfFunctions);
        for (ULONG i = 0; i < exports->NumberOfNames; ++i) {
            const auto* candidate = reinterpret_cast<const char*>(bytes + names[i]);
            size_t length = 0;
            while (length < 128 && candidate[length]) ++length;
            if (!contains(candidate, length, wanted)) continue;
            const auto rva = functions[ordinals[i]];
            if (!rva || rva >= image_size) return nullptr;
            return bytes + rva;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
    return nullptr;
}

bool in_module(const void* address) {
    if (!win32kfull_base || !address) return false;
    const auto value = reinterpret_cast<uint64_t>(address);
    const auto start = reinterpret_cast<uint64_t>(win32kfull_base);
    return value >= start && value < start + win32kfull_size;
}

// The window's owning process, asked through the service itself. The window
// hook is bypassed on purpose: this must see the real PID.
uint32_t window_pid(void* hwnd) {
    if (!hwnd || !query_window.id || !*query_window.original) return 0;
    window guard{query_window.id};
    if (!guard) return 0;
    // Without an open window the call would execute the patch and re-enter
    // this handler; report "nothing" instead of recursing.
    if (!guard) return 0;
    auto* original = *query_window.original;
    return static_cast<uint32_t>(reinterpret_cast<query_window_t>(original)(hwnd, window_process_index));
}

bool tool_window(void* hwnd) {
    const auto pid = window_pid(hwnd);
    return pid && roles::of_pid(pid) == role::tool;
}
}  // namespace

namespace {
ULONG_PTR handler_query_window(void* wnd, ULONG index) {
    if (!query_window.id || !*query_window.original) return 0;
    window guard{query_window.id};
    const auto original = reinterpret_cast<query_window_t>(*query_window.original);
    const auto result = original(wnd, index);
    // WindowProcess is the only index that exposes a PID; the sample sees the
    // tool as process 0, which is what "no such window owner" looks like.
    if (index == window_process_index && result && roles::is_target() &&
        roles::of_pid(static_cast<uint32_t>(result)) == role::tool)
        return 0;
    return result;
}

void* handler_find_window_ex(void* parent, void* after, void* class_name, void* window_name, ULONG type) {
    if (!find_window_ex.id || !*find_window_ex.original) return nullptr;
    window guard{find_window_ex.id};
    // Without an open window the call would execute the patch and re-enter
    // this handler; report "nothing" instead of recursing.
    if (!guard) return 0;
    const auto original = reinterpret_cast<find_window_ex_t>(*find_window_ex.original);
    const auto result = original(parent, after, class_name, window_name, type);
    if (result && roles::is_target() && tool_window(result)) return nullptr;
    return result;
}

NTSTATUS handler_build_hwnd_list(void* desktop, void* next, BOOLEAN children, BOOLEAN immersive,
                                 ULONG thread_id, ULONG count, void** list, PULONG returned) {
    if (!build_hwnd_list.id || !*build_hwnd_list.original)
        return STATUS_DEVICE_NOT_READY;
    NTSTATUS status;
    {
        window guard{build_hwnd_list.id};
    // Without an open window the call would execute the patch and re-enter
    // this handler; report "nothing" instead of recursing.
    if (!guard) return STATUS_DEVICE_NOT_READY;
        const auto original = reinterpret_cast<build_hwnd_list_t>(*build_hwnd_list.original);
        status = original(desktop, next, children, immersive, thread_id, count, list, returned);
    }
    if (!NT_SUCCESS(status) || !list || !returned || !roles::is_target()) return status;
    auto* windows = reinterpret_cast<void**>(list);
    __try {
        ULONG index = 0;
        while (index < *returned) {
            if (!windows[index] || !tool_window(windows[index])) { ++index; continue; }
            for (ULONG i = index; i + 1 < *returned; ++i) windows[i] = windows[i + 1];
            windows[*returned - 1] = nullptr;
            --*returned;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return status;
}

void* handler_get_foreground_window() {
    if (!get_foreground_window.id || !*get_foreground_window.original) return nullptr;
    window guard{get_foreground_window.id};
    // Without an open window the call would execute the patch and re-enter
    // this handler; report "nothing" instead of recursing.
    if (!guard) return 0;
    const auto original = reinterpret_cast<get_foreground_window_t>(*get_foreground_window.original);
    const auto result = original();
    if (!result || !roles::is_target()) return result;
    if (!tool_window(result)) {
        last_foreground = result;
        return result;
    }
    // Keep reporting whatever the sample was allowed to see last, instead of a
    // window that belongs to the debugger.
    return last_foreground;
}

void* handler_window_from_point(point value) {
    if (!window_from_point.id || !*window_from_point.original) return nullptr;
    window guard{window_from_point.id};
    // Without an open window the call would execute the patch and re-enter
    // this handler; report "nothing" instead of recursing.
    if (!guard) return 0;
    const auto original = reinterpret_cast<window_from_point_t>(*window_from_point.original);
    const auto result = original(value);
    if (result && roles::is_target() && tool_window(result)) return nullptr;
    return result;
}

struct install_entry {
    service* slot;
    const char* name;
    void* handler;
};

install_entry entries[] = {
    {&query_window, "NtUserQueryWindow", reinterpret_cast<void*>(&handler_query_window)},
    {&find_window_ex, "NtUserFindWindowEx", reinterpret_cast<void*>(&handler_find_window_ex)},
    {&build_hwnd_list, "NtUserBuildHwndList", reinterpret_cast<void*>(&handler_build_hwnd_list)},
    {&get_foreground_window, "NtUserGetForegroundWindow", reinterpret_cast<void*>(&handler_get_foreground_window)},
    {&window_from_point, "NtUserWindowFromPoint", reinterpret_cast<void*>(&handler_window_from_point)},
};
}  // namespace

bool installed() {
    for (const auto& entry : entries)
        if (entry.slot->id) return true;
    return false;
}

ULONG hook_count() {
    uint32_t count = 0;
    for (const auto& entry : entries)
        if (entry.slot->id) ++count;
    return count;
}

NTSTATUS install() {
    if (installed()) return STATUS_SUCCESS;
    const auto module = find_module("win32kfull.sys");
    if (!module.base || !module.size) return STATUS_NOT_FOUND;
    win32kfull_base = module.base;
    win32kfull_size = module.size;

    uint32_t count = 0;
    for (uint32_t index = 0; index < sizeof(entries) / sizeof(entries[0]); ++index) {
        auto& entry = entries[index];
        if (entry.slot->id) { ++count; continue; }
        // Bring-up knob: WindowHookMask selects which window services to arm.
        if (!service_mask_allows(L"WindowHookMask", index)) continue;
        // Resolve by name from the export table and refuse anything that does
        // not land inside the image we just located.
        auto* address = find_export(win32kfull_base, entry.name, win32kfull_size);
        if (!address || !in_module(address)) continue;
        // The patch itself is built by prepare_hook: only it knows the literal
        // slot the jump reads through.
        uint8_t patch[max_patch]{};
        // Register and publish the entry point before arming: the handler
        // runs on another processor as soon as that processor is armed.
        prepared_hook prepared{};
        if (!NT_SUCCESS(prepare_hook(0, system_token, address, patch,
                                     jump_patch_length, prepared,
                                     entry.handler)))
            continue;
        entry.slot->id = prepared.id;
        // Prefer the trampoline, exactly like the nt profile: it replays the
        // bytes the patch overwrites and jumps back into the function, so the
        // original runs without any page view having to be changed and the
        // call cannot re-enter its own hook if the thread moves to another
        // processor while it is inside the call.
        *entry.slot->original = prepared.trampoline ? prepared.trampoline
                                                    : address;
        if (NT_SUCCESS(arm_hook(prepared))) {
            ++count;
            continue;
        }
        entry.slot->id = 0;
        *entry.slot->original = nullptr;
    }
    return count ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
}

void remove() {
    for (auto& entry : entries) {
        if (!entry.slot->id) continue;
        remove_hook(entry.slot->id);
        entry.slot->id = 0;
        *entry.slot->original = nullptr;
    }
    win32kfull_base = nullptr;
    win32kfull_size = 0;
    last_foreground = nullptr;
}
}  // namespace blook::hide::win32k
