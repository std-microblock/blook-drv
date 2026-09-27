#include "driver/watch.hpp"

#include <ntifs.h>

#include "driver/hooks.hpp"
#include "driver/hv/hv.h"
#include "driver/resources.hpp"

namespace blook::watch {
namespace {
// One watch entry per slot: everything root mode needs is published through
// the (non-paged, stable-address) watch_record before the hypervisor sees the
// spec, so a hit on any processor can complete a dump without taking a lock.
struct watch_entry {
    bool active{};
    bool armed{};
    uint64_t token{};
    watch_spec spec{};
    page_lock page;      // watched page: pinned so its PFN cannot drift away
    page_lock identity;  // owner PEB page
    PEPROCESS process{};
    watch_record* record{};
    uint8_t* buffer{};
    uint32_t buffer_size{};  // == record->dump_size, kept for fetch bounds
};

struct watch_store {
    EX_PUSH_LOCK lock{};
    watch_entry entries[max_watches]{};
    uint64_t next_id{1};
};

watch_store* store{};

uint32_t pid_of(PEPROCESS process) {
    return static_cast<uint32_t>(
        reinterpret_cast<uintptr_t>(PsGetProcessId(process)));
}

// A watched address must be executable *now*: the page has to be fetched
// through the EPT entry this installs, which is only meaningful for committed
// memory. (Arming ahead of the loader mapping the page is a "not committed"
// failure, exactly like check_user_page for hooks.)
NTSTATUS check_page(void* address, bool require_executable) {
    MEMORY_BASIC_INFORMATION info{};
    SIZE_T returned{};
    auto status =
        ZwQueryVirtualMemory(ZwCurrentProcess(), address, MemoryBasicInformation,
                             &info, sizeof(info), &returned);
    if (!NT_SUCCESS(status))
        return status;
    if (info.State != MEM_COMMIT || (info.Protect & PAGE_GUARD))
        return STATUS_INVALID_PAGE_PROTECTION;
    if (require_executable) {
        constexpr auto executable = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                    PAGE_EXECUTE_READWRITE |
                                    PAGE_EXECUTE_WRITECOPY;
        if (!(info.Protect & executable))
            return STATUS_INVALID_PAGE_PROTECTION;
    }
    return STATUS_SUCCESS;
}

void release(watch_entry& entry, bool from_hypervisor) {
    if (entry.armed && from_hypervisor)
        hv::remove_watch(entry.spec.id);
    entry.armed = false;
    entry.active = false;
    if (entry.process) {
        ObDereferenceObject(entry.process);
        entry.process = nullptr;
    }
    entry.identity.reset();
    entry.page.reset();
    if (entry.record) {
        ExFreePoolWithTag(entry.record, 'rwbV');
        entry.record = nullptr;
    }
    if (entry.buffer) {
        ExFreePoolWithTag(entry.buffer, 'bwdV');
        entry.buffer = nullptr;
    }
    entry.buffer_size = 0;
    entry.spec = {};
}

watch_entry* find_locked(uint64_t id) {
    for (auto& entry : store->entries)
        if (entry.active && entry.spec.id == id)
            return &entry;
    return nullptr;
}
}  // namespace

NTSTATUS initialize() {
    NT_ASSERT(!store);
    store = allocate_object<watch_store>();
    return store ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

void shutdown() {
    if (!store)
        return;
    {
        exclusive_lock lock{store->lock};
        for (auto& entry : store->entries)
            if (entry.active)
                release(entry, true);
    }
    delete_object(store);
    store = nullptr;
}

NTSTATUS arm(uint32_t pid, uint64_t token, uint64_t address,
             uint64_t dump_base, uint64_t dump_size, uint64_t& id) {
    if (!store || KeGetCurrentIrql() != PASSIVE_LEVEL || !token)
        return STATUS_INVALID_PARAMETER;
    if (!hv::ghv.running)
        return STATUS_DEVICE_NOT_READY;
    if (!user_address(address) || !dump_size || dump_size > max_dump ||
        !user_address(dump_base) || !user_address(dump_base + dump_size - 1))
        return STATUS_INVALID_PARAMETER;

    exclusive_lock lock{store->lock};
    watch_entry* slot{};
    for (auto& entry : store->entries)
        if (!entry.active) {
            slot = &entry;
            break;
        }
    if (!slot)
        return STATUS_QUOTA_EXCEEDED;

    PEPROCESS process{};
    auto status = PsLookupProcessByProcessId(ULongToHandle(pid), &process);
    if (!NT_SUCCESS(status))
        return status;
    PVOID peb = PsGetProcessPeb(process);
    if (!peb) {
        ObDereferenceObject(process);
        return STATUS_INVALID_ADDRESS;
    }
    auto* const page = reinterpret_cast<void*>(address & ~uint64_t{0xfff});
    KAPC_STATE apc{};
    KeStackAttachProcess(process, &apc);
    status = check_page(reinterpret_cast<void*>(address), true);
    if (NT_SUCCESS(status))
        status = check_page(reinterpret_cast<void*>(dump_base), false);
    if (NT_SUCCESS(status))
        status = slot->page.acquire(page, UserMode, IoReadAccess);
    if (NT_SUCCESS(status))
        status = slot->identity.acquire(peb, UserMode, IoReadAccess);
    KeUnstackDetachProcess(&apc);
    if (!NT_SUCCESS(status)) {
        slot->identity.reset();
        slot->page.reset();
        ObDereferenceObject(process);
        return status;
    }

    // The dump destination: one non-paged buffer plus the record the
    // hypervisor publishes it through. Both have to exist before the first
    // processor can be armed, so a hit can never meet a missing buffer.
    slot->buffer = static_cast<uint8_t*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, dump_size, 'bwdV'));
    slot->record = static_cast<watch_record*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(watch_record), 'rwbV'));
    if (!slot->buffer || !slot->record) {
        release(*slot, false);
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(slot->buffer, dump_size);
    slot->record->state = watch_pending;
    slot->record->dump_base = dump_base;
    slot->record->dump_size = dump_size;
    slot->record->buffer = slot->buffer;
    slot->buffer_size = static_cast<uint32_t>(dump_size);
    slot->process = process;

    auto& spec = slot->spec;
    spec.id = store->next_id++;
    if (!spec.id) {
        release(*slot, false);
        return STATUS_INTEGER_OVERFLOW;
    }
    spec.pfn = slot->page.pfn();
    spec.target = address;
    spec.address_space = slot->identity.pfn();
    spec.identity_address = reinterpret_cast<uint64_t>(peb);
    spec.owner_pid = pid;
    slot->token = token;
    // Register before arming: a hit published through the record resolves the
    // entry by id, and concurrent fetch/disarm calls take the same lock.
    slot->active = true;
    if (!hv::install_watch(spec, slot->record)) {
        release(*slot, false);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    slot->armed = true;
    id = spec.id;
    return STATUS_SUCCESS;
}

NTSTATUS disarm(uint64_t id, uint64_t token) {
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

NTSTATUS fetch(uint64_t id, uint64_t token, uint64_t offset, uint8_t* out,
               uint32_t length, fetch_result& result) {
    if (!store || !id || (length && !out))
        return STATUS_INVALID_PARAMETER;
    result = {};
    exclusive_lock lock{store->lock};
    auto* entry = find_locked(id);
    if (!entry)
        return STATUS_NOT_FOUND;
    if (entry->token != token)
        return STATUS_ACCESS_DENIED;
    const auto* record = entry->record;
    result.state = record->state;
    result.total = record->dump_size;
    if (record->state == watch_hit) {
        result.hit_rip = record->hit_rip;
        result.hit_cr3 = record->hit_cr3;
        if (offset < entry->buffer_size && out) {
            const auto available = entry->buffer_size - offset;
            const auto take = length < available ? length
                                                 : static_cast<uint32_t>(available);
            RtlCopyMemory(out, entry->buffer + offset, take);
            result.copied = take;
        }
    }
    return STATUS_SUCCESS;
}

void rebind_if_copied(PEPROCESS process, uint64_t begin, uint64_t end) {
    if (!store || KeGetCurrentIrql() != PASSIVE_LEVEL || !process)
        return;
    if (!hv::ghv.running)
        return;
    const auto pid = pid_of(process);
    exclusive_lock lock{store->lock};
    bool candidate = false;
    for (const auto& entry : store->entries)
        if (entry.active && entry.spec.owner_pid == pid &&
            entry.spec.target >= begin && entry.spec.target < end)
            candidate = true;
    if (!candidate)
        return;
    KAPC_STATE apc{};
    KeStackAttachProcess(process, &apc);
    for (auto& entry : store->entries) {
        if (!entry.active || entry.spec.owner_pid != pid ||
            entry.spec.target < begin || entry.spec.target >= end)
            continue;
        page_lock fresh;
        auto* const page =
            reinterpret_cast<void*>(entry.spec.target & ~uint64_t{0xfff});
        if (!NT_SUCCESS(fresh.acquire(page, UserMode, IoReadAccess)))
            continue;
        const auto pfn = fresh.pfn();
        if (!pfn || pfn == entry.spec.pfn)
            continue;
        hv::remove_watch(entry.spec.id);
        entry.page.reset();
        entry.page = static_cast<page_lock&&>(fresh);
        entry.spec.pfn = pfn;
        // A failed re-install leaves the entry registered but unarmed; the
        // caller still sees it and can disarm/refetch.
        entry.armed = hv::install_watch(entry.spec, entry.record);
    }
    KeUnstackDetachProcess(&apc);
}

void revoke_session(uint64_t token) {
    if (!store || !token || token == system_token ||
        KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;
    exclusive_lock lock{store->lock};
    for (auto& entry : store->entries)
        if (entry.active && entry.token == token)
            release(entry, true);
}

void revoke_process(uint32_t pid) {
    if (!store || !pid || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;
    exclusive_lock lock{store->lock};
    for (auto& entry : store->entries)
        if (entry.active && entry.spec.owner_pid == pid)
            release(entry, true);
}
}  // namespace blook::watch
