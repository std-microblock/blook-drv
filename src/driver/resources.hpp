#pragma once
#include <ntifs.h>
inline void* operator new(size_t, void* memory) noexcept {
    return memory;
}
inline void operator delete(void*, void*) noexcept {}
#include "policy/integer.hpp"

// Part of the process interface the minimal filesystem driver include set does
// not pull in, but which ntoskrnl exports and which a PEB-aware driver needs.
extern "C" {
NTSYSAPI PVOID __stdcall PsGetProcessPeb(PEPROCESS process);
NTSYSAPI PVOID __stdcall PsGetProcessWow64Process(PEPROCESS process);
NTSYSAPI PCHAR __stdcall PsGetProcessImageFileName(PEPROCESS process);
}

namespace blook {
class exclusive_lock final {
    EX_PUSH_LOCK* lock_;

   public:
    explicit exclusive_lock(EX_PUSH_LOCK& lock) : lock_(&lock) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(lock_);
    }
    ~exclusive_lock() {
        ExReleasePushLockExclusive(lock_);
        KeLeaveCriticalRegion();
    }
    exclusive_lock(const exclusive_lock&) = delete;
    exclusive_lock& operator=(const exclusive_lock&) = delete;
};
class page_lock final {
    PMDL mdl_{};
    void* mapping_{};

   public:
    page_lock() = default;
    ~page_lock() { reset(); }
    page_lock(const page_lock&) = delete;
    page_lock& operator=(const page_lock&) = delete;
    NTSTATUS acquire(void* page, KPROCESSOR_MODE mode,
                     LOCK_OPERATION operation = IoReadAccess) {
        reset();
        mdl_ = IoAllocateMdl(page, PAGE_SIZE, FALSE, FALSE, nullptr);
        if (!mdl_)
            return STATUS_INSUFFICIENT_RESOURCES;
        __try {
            MmProbeAndLockPages(mdl_, mode, operation);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            auto status = GetExceptionCode();
            IoFreeMdl(mdl_);
            mdl_ = nullptr;
            return status;
        }
        mapping_ = MmGetSystemAddressForMdlSafe(
            mdl_, NormalPagePriority | MdlMappingNoExecute);
        if (!mapping_) {
            reset();
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        return STATUS_SUCCESS;
    }
    void reset() {
        if (mdl_) {
            MmUnlockPages(mdl_);
            IoFreeMdl(mdl_);
            mdl_ = nullptr;
        }
        mapping_ = nullptr;
    }
    uint64_t pfn() const { return mdl_ ? MmGetMdlPfnArray(mdl_)[0] : 0; }
    const uint8_t* data() const {
        return static_cast<const uint8_t*>(mapping_);
    }
};
template <class T>
T* allocate_object() {
    auto memory = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(T), 'oklB');
    return memory ? new (memory) T{} : nullptr;
}
template <class T>
void delete_object(T* object) {
    if (object) {
        object->~T();
        ExFreePoolWithTag(object, 'oklB');
    }
}
}  // namespace blook
