#include <ntifs.h>
// MSVC emits deleting destructors even for placement-constructed kernel
// objects.
void operator delete(void* memory) noexcept {
    if (memory)
        ExFreePoolWithTag(memory, 'oklB');
}
void operator delete(void* memory, size_t) noexcept {
    if (memory)
        ExFreePoolWithTag(memory, 'oklB');
}
