#pragma once
#include <ntifs.h>

#include "policy/hook.hpp"

// Execute watches (dump-on-execute), the anti-self-decrypting-shell feature.
//
// A watch arms the physical page of a chosen address in a target process
// not-executable. The first time that process executes exactly that address,
// the hypervisor copies a configured range of the process address space into
// a non-paged record - the unpacked code, dumped from physical memory, which
// no user-mode API hook of the shell can interfere with. The session then
// fetches the record over IOCTL. Watches are one-shot: after the dump the
// page runs unarmed again.
//
// Same ownership model as hooks: a watch belongs to the session that created
// it and is dropped with the session or with the target process.
namespace blook::watch {
struct fetch_result {
    uint32_t state{};  // watch_pending / watch_hit
    uint32_t copied{};
    uint64_t total{};
    uint64_t hit_rip{};
    uint64_t hit_cr3{};
};

NTSTATUS initialize();
void shutdown();

// Arm a watch on `address` (a user-mode VA in `pid`), dumping
// [dump_base, dump_base + dump_size) of the same process on the first hit.
NTSTATUS arm(uint32_t pid, uint64_t token, uint64_t address,
             uint64_t dump_base, uint64_t dump_size, uint64_t& id);
NTSTATUS disarm(uint64_t id, uint64_t token);

// Copy state and up to `length` bytes of the dump buffer at `offset` into the
// caller-provided (IOCTL system) buffer.
NTSTATUS fetch(uint64_t id, uint64_t token, uint64_t offset, uint8_t* out,
               uint32_t length, fetch_result& result);

// Copy-on-write companion of blook::rebind_hooks_if_copied: a watched image
// page privatised by NtProtectVirtualMemory / NtWriteVirtualMemory moves the
// watch to the new physical page, otherwise it would never fire.
void rebind_if_copied(PEPROCESS process, uint64_t begin, uint64_t end);

void revoke_session(uint64_t token);
void revoke_process(uint32_t pid);
}  // namespace blook::watch
