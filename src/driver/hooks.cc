#include "policy/x86_length.hpp"
#include "hooks.hpp"

#include <ntifs.h>

#include "driver/hv/hv.h"
#include "resources.hpp"

namespace blook {
namespace {
struct hook_entry {
    bool active{};
    uint64_t token{};
    hook_spec spec{};
    page_lock page;  // mapping and PFN of the patched page
    page_lock
        identity;  // pinned per-process identity page (PEB), user hooks only
    PEPROCESS process{};  // referenced owner, user hooks only
};

struct hook_store {
    EX_PUSH_LOCK lock{};
    hook_entry entries[max_hooks];
    uint64_t next_id{1};
};

hook_store* store{};

hook_entry* find_locked(uint64_t id) {
    for (auto& entry : store->entries)
        if (entry.active && entry.spec.id == id)
            return &entry;
    return nullptr;
}

void release(hook_entry& entry, bool remove_from_hypervisor) {
    if (entry.active && remove_from_hypervisor)
        hv::remove(entry.spec.id);
    entry.active = false;
    if (entry.process) {
        ObDereferenceObject(entry.process);
        entry.process = nullptr;
    }
    entry.identity.reset();
    entry.page.reset();
    entry.spec = {};
}

bool duplicate_page(const hook_entry& candidate, const hook_spec& spec,
                    uint64_t pfn) {
    if (!candidate.active || candidate.spec.pfn != pfn)
        return false;
    // Only one shadow page exists per physical page, so a page can never carry
    // two hooks unless they belong to the same address space. Kernel hooks are
    // global, so they collide with everything.
    const bool global = candidate.spec.domain == hook_domain::kernel ||
                        spec.domain == hook_domain::kernel;
    return global || candidate.spec.address_space == spec.address_space;
}

// A user hook only makes sense on committed executable memory: patching a page
// the target never executes would be an unmapped PFN trap rather than a hook.
NTSTATUS check_user_page(void* target) {
    MEMORY_BASIC_INFORMATION info{};
    SIZE_T returned{};
    auto status =
        ZwQueryVirtualMemory(ZwCurrentProcess(), target, MemoryBasicInformation,
                             &info, sizeof(info), &returned);
    if (!NT_SUCCESS(status))
        return status;
    if (info.State != MEM_COMMIT || (info.Protect & PAGE_GUARD))
        return STATUS_INVALID_PAGE_PROTECTION;
    constexpr auto executable = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (!(info.Protect & executable))
        return STATUS_INVALID_PAGE_PROTECTION;
    return STATUS_SUCCESS;
}
}  // namespace

// Bring-up log: a plain file the runner can read without a debugger and
// without the registry. Diagnostics only, PASSIVE_LEVEL only, one line per
// write.
void bringup_write(const char* label, uint32_t value, bool have_value) {
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return;
    UNICODE_STRING path;
    RtlInitUnicodeString(&path, L"\\??\\D:\\blook-drv\\.cache\\driver.log");
    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr,
                               nullptr);
    HANDLE file{};
    IO_STATUS_BLOCK status{};
    if (!NT_SUCCESS(ZwCreateFile(&file, FILE_APPEND_DATA | SYNCHRONIZE, &attributes,
                                 &status, nullptr, FILE_ATTRIBUTE_NORMAL,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                                 FILE_SYNCHRONOUS_IO_NONALERT | FILE_WRITE_THROUGH,
                                 nullptr, 0)))
        return;
    char line[96];
    size_t n = 0;
    while (label[n] && n < sizeof(line) - 24) { line[n] = label[n]; ++n; }
    if (have_value) {
        static const char digits[] = "0123456789abcdef";
        char text[9];
        for (int i = 0; i < 8; ++i)
            text[i] = digits[(value >> ((7 - i) * 4)) & 0xf];
        line[n++] = ' ';
        line[n++] = '0';
        line[n++] = 'x';
        int first = 0;
        while (first < 7 && text[first] == '0') ++first;
        for (int i = first; i < 8; ++i) line[n++] = text[i];
    }
    line[n++] = '\r';
    line[n++] = '\n';
    ZwWriteFile(file, nullptr, nullptr, nullptr, &status, line, (ULONG)n,
                nullptr, nullptr);
    ZwClose(file);
}

namespace {
// Bring-up switches. Every (value, bit) pair is resolved once and then cached:
// service_mask_allows() is called from inside the hooked service itself, and a
// registry read plus a log line per service call turned every
// NtQuerySystemInformation call in the system into a handful of registry and
// file operations. That is a hot-path cost and an IRQL hazard - Zw* wants
// PASSIVE_LEVEL, which a hooked service is not necessarily entered at. A pair
// that is not resolved yet and cannot be resolved right now counts as allowed,
// exactly like a missing value did before.
struct mask_switch {
    const wchar_t* value{};
    uint32_t bit{};
    uint8_t allowed{0xff};  // 0xff = not resolved yet
};
mask_switch mask_switches[16]{};

// true = the value was read; false = treat it as allowed. Only ever called at
// PASSIVE_LEVEL.
bool read_mask_switch(const wchar_t* value, uint32_t bit, bool& allowed) {
    UNICODE_STRING path = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\BlookDrv");
    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr,
                               nullptr);
    HANDLE key{};
    if (!NT_SUCCESS(ZwOpenKey(&key, KEY_QUERY_VALUE, &attributes))) {
        bringup_write("mask: key unreadable, allowing", bit, true);
        return false;
    }
    struct {
        KEY_VALUE_PARTIAL_INFORMATION information;
        uint8_t data[64];
    } buffer{};
    UNICODE_STRING name{};
    RtlInitUnicodeString(&name, value);
    ULONG length{};
    const auto status = ZwQueryValueKey(key, &name, KeyValuePartialInformation,
                                        &buffer, sizeof(buffer), &length);
    ZwClose(key);
    if (!NT_SUCCESS(status) || buffer.information.Type != REG_DWORD ||
        buffer.information.DataLength < sizeof(uint32_t)) {
        bringup_write("mask: value unreadable, allowing", bit, true);
        return false;
    }
    const auto mask =
        *reinterpret_cast<const uint32_t*>(buffer.information.Data);
    bringup_write("mask: raw", mask, true);
    allowed = (mask & (1u << bit)) != 0;
    return true;
}
}  // namespace

bool service_mask_allows(const wchar_t* value, uint32_t bit) {
    if (!value || bit >= 32)
        return false;
    for (const auto& slot : mask_switches)
        if (slot.allowed != 0xff && slot.value == value && slot.bit == bit)
            return slot.allowed != 0;
    // Outside PASSIVE_LEVEL the switch cannot be read at all, so do not pin a
    // default - the caller gets "allowed" and the next PASSIVE call resolves
    // it for real. A value that *was* readable but missing (or unreadable in a
    // pass at PASSIVE_LEVEL) is a decision like any other: it stays "allowed",
    // exactly like a missing value always did, and it is logged once.
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return true;
    bool allowed = true;
    read_mask_switch(value, bit, allowed);
    for (auto& slot : mask_switches)
        if (slot.allowed == 0xff) {
            slot.value = value;
            slot.bit = bit;
            slot.allowed = allowed ? 1 : 0;
            break;
        }
    return allowed;
}

NTSTATUS initialize_hooks() {
    store = allocate_object<hook_store>();
    return store ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

void shutdown_hooks() {
    if (!store)
        return;
    {
        exclusive_lock lock{store->lock};
        for (auto& entry : store->entries)
            release(entry, true);
    }
    delete_object(store);
    store = nullptr;
}

namespace {
// Length decoder for the prologue of a hooked function. Patching a fixed number
// of bytes can cut an instruction in half, and a trampoline that replays half
// an instruction jumps into nowhere (observed as a double fault inside the
// handler). Only the shapes a Windows kernel function starts with are decoded;
// anything unrecognised makes the caller skip the hook instead of guessing.
size_t instruction_length(const uint8_t* code, size_t available) {
    size_t i = 0;
    for (; i < available && i < 8; ++i) {
        const auto byte = code[i];
        if (byte == 0x66 || byte == 0x67 || byte == 0xf2 || byte == 0xf3 ||
            byte == 0xf0 || byte == 0x65 || byte == 0x64)
            continue;
        break;
    }
    if (i >= available)
        return 0;
    auto const rex = code[i];
    if ((rex & 0xf0) == 0x40)
        ++i;
    if (i >= available)
        return 0;
    const auto opcode = code[i++];
    const auto imm = code + i;
    switch (opcode) {
        case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55:
        case 0x56: case 0x57: case 0x58: case 0x59: case 0x5a: case 0x5b:
        case 0x5c: case 0x5d: case 0x5e: case 0x5f: case 0x90: case 0xcc:
        case 0x98: case 0x99: case 0x9c: case 0x9d:
            return i;
        case 0xb8: case 0xb9: case 0xba: case 0xbb: case 0xbc: case 0xbd:
        case 0xbe: case 0xbf:
            if (i + 4 > available)
                return 0;
            return i + ((rex & 0x08) ? 8 : 4);
        case 0xe8: case 0xe9:
            return i + 4 <= available ? i + 4 : 0;
        case 0xeb: case 0x6a: case 0xb0: case 0xb1: case 0xb2: case 0xb3:
        case 0xb4: case 0xb5: case 0xb6: case 0xb7:
            return i + 1 <= available ? i + 1 : 0;
        case 0x0f:
            if (i >= available)
                return 0;
            return i + 1;  // nop/syscall/bx-style two byte opcodes
        case 0x89: case 0x8b: case 0x8d: case 0x83: case 0x81: case 0x2b:
        case 0x03: case 0x29: case 0x01: case 0x31: case 0x33: {
            if (i >= available)
                return 0;
            const auto modrm = code[i];
            size_t length = i + 1;
            const auto mod = modrm >> 6;
            const auto rm = modrm & 7;
            const bool sib = rm == 4;
            if (sib && mod != 3) {
                if (length >= available)
                    return 0;
                const auto sib_byte = code[length];
                ++length;
                if (mod == 0 && (sib_byte & 7) == 5)
                    length += 4;
            }
            if (mod == 0 && rm == 5)
                length += 4;
            else if (mod == 1)
                length += 1;
            else if (mod == 2)
                length += 4;
            if (opcode == 0x83)
                length += 1;
            if (opcode == 0x81)
                length += 4;
            return length <= available ? length : 0;
        }
        default:
            return 0;
    }
}
}  // namespace

namespace {
uint64_t jump_literals[2 * blook::max_hooks]{};
// Where the most recently prepared trampoline lives, so a dump can show its
// bytes without scanning the whole pool.
uint64_t last_trampoline_address{};
}  // namespace

uint64_t* hook_jump_literal(uint32_t slot) {
    if (slot >= 2 * blook::max_hooks) return nullptr;
    return &jump_literals[slot];
}

namespace {
// Bring-up: which step of prepare_hook did this attempt reach? Any early
// return leaves the last value behind, which is the whole point.
}  // namespace
NTSTATUS prepare_hook(uint32_t pid, uint64_t token, void* target,
                      const uint8_t* patch, size_t length,
                      prepared_hook& prepared, const void* destination) {
    if (!store || KeGetCurrentIrql() != PASSIVE_LEVEL || !target || !patch)
        return STATUS_INVALID_PARAMETER;
    const auto address = reinterpret_cast<uint64_t>(target);
    if (!valid_patch(address, length))
        return STATUS_INVALID_PARAMETER;
    if (!hv::ghv.running)
        return STATUS_DEVICE_NOT_READY;

    // Everything that consumes hook_spec::original - the hypervisor shadow
    // copy above all - expects a mapping of the whole page with the in-page
    // offset preserved: shadow[i] must hold the byte at page offset i, and the
    // patch belongs at shadow[target & 0xfff]. Locking the *target* instead
    // returns a mapping whose first byte *is* the target, so the shadow came
    // out holding the code from the target onward, shifted by the target page
    // offset. The entry patch still landed correctly (the EPT preserves the
    // in-page offset), which is why the hook fired and looked healthy while
    // every other entry point on that page - the other services sharing the
    // 4 KiB page, and the body of the hooked function itself whenever it was
    // reached from anywhere but offset zero - executed bytes from the wrong
    // offset and ended in a return to zero. Lock the page, not the target.
    auto* const page = reinterpret_cast<void*>(address & ~uint64_t{0xfff});

    hook_spec spec{};
    hook_entry* slot{};
    exclusive_lock lock{store->lock};
    for (auto& entry : store->entries)
        if (!entry.active) {
            slot = &entry;
            break;
        }
    if (!slot)
        return STATUS_QUOTA_EXCEEDED;

    NTSTATUS status = STATUS_SUCCESS;
    if (pid) {
        if (!user_address(address))
            return STATUS_INVALID_ADDRESS;
        PEPROCESS process{};
        status = PsLookupProcessByProcessId(ULongToHandle(pid), &process);
        if (!NT_SUCCESS(status))
            return status;
        PVOID peb = PsGetProcessPeb(process);
        if (!peb) {
            ObDereferenceObject(process);
            return STATUS_INVALID_ADDRESS;
        }
        KAPC_STATE apc{};
        KeStackAttachProcess(process, &apc);
        status = check_user_page(target);
        if (NT_SUCCESS(status))
            status = slot->page.acquire(page, UserMode, IoReadAccess);
        if (NT_SUCCESS(status) &&
            (reinterpret_cast<uint64_t>(slot->page.data()) & 0xfff))
            status = STATUS_INVALID_PARAMETER;
        // Pinning the identity page keeps the root mode translation of that
        // address valid for as long as the hook lives.
        if (NT_SUCCESS(status))
            status = slot->identity.acquire(peb, UserMode, IoReadAccess);
        KeUnstackDetachProcess(&apc);
        if (!NT_SUCCESS(status)) {
            slot->identity.reset();
            slot->page.reset();
            ObDereferenceObject(process);
            return status;
        }
        spec.domain = hook_domain::user;
        spec.owner_pid = pid;
        spec.address_space = slot->identity.pfn();
        spec.identity_address = reinterpret_cast<uint64_t>(peb);
        slot->process = process;
    } else {
        if (address < reinterpret_cast<uint64_t>(MmSystemRangeStart))
            return STATUS_INVALID_ADDRESS;
        spec.domain = hook_domain::kernel;
        status = slot->page.acquire(page, KernelMode, IoReadAccess);
        if (!NT_SUCCESS(status))
            return status;
        if (reinterpret_cast<uint64_t>(slot->page.data()) & 0xfff) {
            slot->page.reset();
            return STATUS_INVALID_PARAMETER;
        }
    }

    const auto pfn = slot->page.pfn();
    for (const auto& entry : store->entries)
        if (duplicate_page(entry, spec, pfn)) {
            release(*slot, false);
            return STATUS_OBJECT_NAME_COLLISION;
        }
    if (store->next_id == 0) {
        release(*slot, false);
        return STATUS_INTEGER_OVERFLOW;
    }

    spec.id = store->next_id++;
    spec.pfn = pfn;
    spec.target = address;
    spec.original = slot->page.data();
    // Cover whole instructions: a patch whose length lands in the middle of one
    // makes the processor resume inside it, and a trampoline that replays half
    // an instruction jumps into nowhere (both were observed as a double fault
    // inside the handler). `length` is the minimum - the jump itself - and the
    // real length is the instruction boundary at or after it. A prologue that
    // cannot be decoded skips the hook: a missing hook is invisible, a corrupt
    // one is a bugcheck.
    size_t covered = length;
    {
        const auto offset = address & 0xfff;
        const auto* page_code =
            static_cast<const uint8_t*>(slot->page.data()) + offset;
        const auto room = 4096 - offset;
        covered = 0;
        while (covered < length) {
            const auto step = blook::x86::instruction_length(page_code + covered, room - covered);
            if (!step)
                return STATUS_INVALID_PARAMETER;
            covered += step;
        }
        if (covered > max_patch || covered > room)
            return STATUS_INVALID_PARAMETER;
    }

    spec.length = static_cast<uint32_t>(covered);
    if (destination) {
        // Built here: the id, and with it the literal slot the jump reads
        // through, is only known now. Out of reach means: do not hook.
        auto* const literal = hook_jump_literal(spec.id);
        uint8_t entry[max_patch]{};
        if (!literal ||
            !build_jump_patch(entry, address, reinterpret_cast<uint64_t>(literal)))
            return STATUS_NOT_SUPPORTED;
        *literal = reinterpret_cast<uint64_t>(destination);
        for (size_t i = 0; i < covered; ++i)
            spec.patch[i] = i < jump_patch_length ? entry[i] : 0x90;
    } else {
        for (size_t i = 0; i < covered; ++i)
            spec.patch[i] = i < length ? patch[i] : 0x90;
    }

    // Trampoline: the overwritten bytes followed by a jump back to the rest of
    // the function. The handler calls this to reach the original, which is how
    // the call-original window is avoided: no EPT view of kernel code has to be
    // turned executable, on any processor, for a call to the real service.
    {
        constexpr size_t back_jump_size = jump_patch_length + 8;
        const auto size = covered + back_jump_size;
        // MmProtectMdlSystemAddress changes the protection of whole pages, so
        // the trampoline may not share its page with other pool blocks: the
        // small pool allocation used to live in a shared page, the protection
        // call failed, no trampoline was published and the handler ended up
        // calling the patched entry (unbounded recursion, 0x7f double fault).
        // The raw allocation is intentionally kept alive with the hook so the
        // page-aligned slice inside it stays valid.
        const auto raw_size = size + PAGE_SIZE;
        auto* raw = static_cast<uint8_t*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, raw_size, 'trkB'));
        auto* trampoline = raw ? reinterpret_cast<uint8_t*>(
            (reinterpret_cast<unsigned long long>(raw) + PAGE_SIZE - 1) &
            ~(static_cast<unsigned long long>(PAGE_SIZE) - 1)) : nullptr;
        bringup_write("trampoline: pool", trampoline ? 1u : 0u, true);
        if (trampoline) {
            // Everything is written through ONE mapping. The MDL system
            // address is what the entry patch's literal points at and what the
            // handler executes, and on this machine it is not the pool address
            // the allocation returned: writing to the pool address left the
            // published page holding something else entirely (a dump showed
            // permission-looking bytes where the prologue should have been,
            // so the service resumed at target+covered with its prologue never
            // executed and faulted at +0x3e).
            auto* mdl = IoAllocateMdl(trampoline, static_cast<ULONG>(size),
                                      FALSE, FALSE, nullptr);
            bringup_write("trampoline: mdl", mdl ? 1u : 0u, true);
            uint8_t* code = nullptr;
            if (mdl) {
                // MmProtectMdlSystemAddress wants a locked MDL; the flags that
                // MmBuildMdlForNonPagedPool sets were not enough here (log:
                // pool 1, mdl 1, mapped-protected 0). MmProbeAndLockPages is
                // the documented way to lock a non-paged buffer, and it can
                // raise, so guard it.
                // Verified order: MmProtectMdlSystemAddress only accepts MDLs
                // whose pages carry a *system* mapping, and it answers
                // STATUS_NOT_SUPPORTED (0xC00000BB) otherwise - which is
                // exactly what the log showed. So map first, protect second,
                // and run the trampoline through that executable mapping.
                __try {
                    MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    bringup_write("trampoline: probe raised",
                                  static_cast<uint32_t>(GetExceptionCode()), true);
                }
                auto* mapped = static_cast<uint8_t*>(
                    MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached,
                                                 nullptr, FALSE,
                                                 NormalPagePriority));
                if (mapped) {
                    const auto protect = MmProtectMdlSystemAddress(
                        mdl, PAGE_EXECUTE_READWRITE);
                    bringup_write("trampoline: protect status",
                                  static_cast<uint32_t>(protect), true);
                    if (NT_SUCCESS(protect))
                        code = mapped;
                }
            }
            bringup_write("trampoline: mapped-protected", code ? 1u : 0u, true);
            if (code) {
                // Same source as the shadow: the locked page mapping plus the
                // in-page offset. Reading the live target address instead only
                // works while that address space is the current one - which a
                // user hook is no longer by this point, prepare_hook has
                // detached - and it can fault where the locked mapping cannot.
                memcpy(code, spec.original + (address & 0xfff), covered);
                const auto back = address + covered;
                auto* const literal = reinterpret_cast<uint64_t*>(
                    code + covered + jump_patch_length);
                *literal = back;
                uint8_t back_patch[max_patch]{};
                // The literal sits jump_patch_length bytes past the patch, so
                // the displacement always fits; the check cannot fail here.
                (void)build_jump_patch(back_patch,
                                       reinterpret_cast<uint64_t>(code + covered),
                                       reinterpret_cast<uint64_t>(literal));
                for (size_t i = 0; i < jump_patch_length; ++i)
                    code[covered + i] = back_patch[i];
                prepared.trampoline = code;
                last_trampoline_address = reinterpret_cast<uint64_t>(code);
            }
        }
    }

    // Publish the record before anything can execute the patch: the handler
    // the patch jumps to has nothing but this registry to rely on.
    slot->token = token;
    slot->spec = spec;
    slot->active = true;
    prepared.id = spec.id;
    prepared.spec = spec;
    return STATUS_SUCCESS;
}

NTSTATUS arm_hook(const prepared_hook& prepared) {
    if (!store || !prepared.id)
        return STATUS_INVALID_PARAMETER;
    if (!hv::ghv.running)
        return STATUS_DEVICE_NOT_READY;
    exclusive_lock lock{store->lock};
    auto* entry = find_locked(prepared.id);
    if (!entry)
        return STATUS_NOT_FOUND;
    if (!hv::install(prepared.spec)) {
        release(*entry, false);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    return STATUS_SUCCESS;
}

void cancel_hook(const prepared_hook& prepared) {
    if (!store || !prepared.id)
        return;
    exclusive_lock lock{store->lock};
    if (auto* entry = find_locked(prepared.id))
        release(*entry, false);
}

NTSTATUS install_hook(uint32_t pid, uint64_t token, void* target,
                      const uint8_t* patch, size_t length, uint64_t& id) {
    prepared_hook prepared{};
    auto status = prepare_hook(pid, token, target, patch, length, prepared);
    if (!NT_SUCCESS(status))
        return status;
    status = arm_hook(prepared);
    if (!NT_SUCCESS(status))
        return status;
    id = prepared.id;
    return STATUS_SUCCESS;
}

NTSTATUS remove_hook(uint64_t id) {
    if (!store || !id)
        return STATUS_INVALID_PARAMETER;
    exclusive_lock lock{store->lock};
    auto* entry = find_locked(id);
    if (!entry)
        return STATUS_NOT_FOUND;
    release(*entry, true);
    return STATUS_SUCCESS;
}

NTSTATUS refresh_hook(uint64_t id) {
    if (!store || KeGetCurrentIrql() != PASSIVE_LEVEL || !id)
        return STATUS_INVALID_PARAMETER;
    if (!hv::ghv.running)
        return STATUS_DEVICE_NOT_READY;
    exclusive_lock lock{store->lock};
    if (!find_locked(id))
        return STATUS_NOT_FOUND;
    hv::refresh(id);
    return STATUS_SUCCESS;
}

NTSTATUS remove_owned_hook(uint64_t id, uint64_t token) {
    if (!store || !id)
        return STATUS_INVALID_PARAMETER;
    exclusive_lock lock{store->lock};
    auto* entry = find_locked(id);
    if (!entry)
        return STATUS_NOT_FOUND;
    if (entry->token != token)
        return STATUS_ACCESS_DENIED;
    release(*entry, true);
    return STATUS_SUCCESS;
}

NTSTATUS refresh_owned_hook(uint64_t id, uint64_t token) {
    if (!store || !id)
        return STATUS_INVALID_PARAMETER;
    if (!hv::ghv.running)
        return STATUS_DEVICE_NOT_READY;
    exclusive_lock lock{store->lock};
    auto* entry = find_locked(id);
    if (!entry)
        return STATUS_NOT_FOUND;
    if (entry->token != token)
        return STATUS_ACCESS_DENIED;
    hv::refresh(id);
    return STATUS_SUCCESS;
}

bool hook_present(uint64_t id) {
    if (!store || !id)
        return false;
    exclusive_lock lock{store->lock};
    return find_locked(id) != nullptr;
}

bool begin_hook_window(uint64_t id) {
    if (!store || !id)
        return false;
    return hv::begin_window(id);
}

void end_hook_window(uint64_t id) {
    if (store && id)
        hv::end_window(id);
}

void revoke_process(uint32_t pid) {
    if (!store || !pid || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;
    exclusive_lock lock{store->lock};
    for (auto& entry : store->entries)
        if (entry.active && entry.spec.owner_pid == pid)
            release(entry, true);
}

void restore_all() {
    if (!store || !hv::ghv.running)
        return;
    exclusive_lock lock{store->lock};
    // A hook whose page is gone cannot be republished; it stays in the
    // registry so that a later remove still clears it.
    for (auto& entry : store->entries)
        if (entry.active)
            (void)hv::install(entry.spec);
}

uint32_t active_hook_count() {
    if (!store)
        return 0;
    exclusive_lock lock{store->lock};
    uint32_t count{};
    for (const auto& entry : store->entries)
        if (entry.active)
            ++count;
    return count;
}

uint32_t user_hook_count(uint32_t pid) {
    if (!store)
        return 0;
    exclusive_lock lock{store->lock};
    uint32_t count{};
    for (const auto& entry : store->entries)
        if (entry.active && entry.spec.domain == hook_domain::user &&
            entry.spec.owner_pid == pid)
            ++count;
    return count;
}
}  // namespace blook
