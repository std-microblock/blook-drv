#include "roles.hpp"

#include "driver/resources.hpp"
#include "policy/names.hpp"

namespace blook::roles {
namespace {
constexpr size_t max_pinned = 32;

struct pinned_entry {
    uint32_t pid{};
    role value{role::other};
    bool used{};
};

EX_PUSH_LOCK pinned_lock{};
pinned_entry pinned[max_pinned]{};

uint32_t pid_of(HANDLE value) {
    return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(value));
}

role lookup_pinned(uint32_t pid) {
    if (!pid)
        return role::other;
    exclusive_lock lock{pinned_lock};
    for (const auto& entry : pinned)
        if (entry.used && entry.pid == pid)
            return entry.value;
    return role::other;
}

role classify_process(PEPROCESS process) {
    if (!process)
        return role::other;
    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        PUNICODE_STRING name{};
        if (NT_SUCCESS(SeLocateProcessImageName(process, &name)) && name) {
            const auto found =
                classify(name->Buffer, name->Length / sizeof(wchar_t));
            ExFreePool(name);
            return found;
        }
    }
    // Fixed size name inside the EPROCESS: no allocation, safe at any IRQL.
    const auto* short_name = PsGetProcessImageFileName(process);
    if (!short_name)
        return role::other;
    size_t length = 0;
    while (length < 15 && short_name[length])
        ++length;
    return classify_ascii(short_name, length);
}
}  // namespace

role pinned_role(uint32_t pid) {
    return lookup_pinned(pid);
}

role of_process(PEPROCESS process) {
    if (!process)
        return role::other;
    const auto pinned_role = lookup_pinned(pid_of(PsGetProcessId(process)));
    if (pinned_role != role::other)
        return pinned_role;
    return classify_process(process);
}

role of_pid(uint32_t pid) {
    if (!pid)
        return role::other;
    const auto pinned_role = lookup_pinned(pid);
    if (pinned_role != role::other)
        return pinned_role;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return role::other;
    PEPROCESS process{};
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(pid), &process)))
        return role::other;
    const auto found = classify_process(process);
    ObDereferenceObject(process);
    return found;
}

role of_current() {
    return of_process(PsGetCurrentProcess());
}

bool pid_is_target(uint32_t pid) {
    return of_pid(pid) == role::target;
}
bool pid_is_tool(uint32_t pid) {
    return of_pid(pid) == role::tool;
}

void pin(uint32_t pid, role value) {
    if (!pid)
        return;
    exclusive_lock lock{pinned_lock};
    pinned_entry* free_slot{};
    for (auto& entry : pinned) {
        if (entry.used && entry.pid == pid) {
            entry.value = value;
            return;
        }
        if (!entry.used && !free_slot)
            free_slot = &entry;
    }
    if (free_slot) {
        free_slot->used = true;
        free_slot->pid = pid;
        free_slot->value = value;
    }
}

void unpin(uint32_t pid) {
    exclusive_lock lock{pinned_lock};
    for (auto& entry : pinned)
        if (entry.used && entry.pid == pid)
            entry = {};
}

void reset() {
    exclusive_lock lock{pinned_lock};
    for (auto& entry : pinned)
        entry = {};
}
}  // namespace blook::roles
