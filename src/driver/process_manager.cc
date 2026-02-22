#include "process_manager.hpp"

#include <ntifs.h>

namespace process_manager {

// Name resolution

bool get_name_by_pid(HANDLE pid, PUNICODE_STRING out) {
    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status))
        return false;

    bool result = get_name_by_eprocess(process, out);
    ObDereferenceObject(process);
    return result;
}

bool get_name_by_eprocess(PEPROCESS process, PUNICODE_STRING out) {
    PUNICODE_STRING name = nullptr;
    NTSTATUS status = SeLocateProcessImageName(process, &name);
    if (!NT_SUCCESS(status))
        return false;

    out->Length = name->Length;
    out->MaximumLength = name->MaximumLength;
    out->Buffer = static_cast<PWCH>(
        ExAllocatePoolWithTag(NonPagedPool, name->MaximumLength, 'pmgr'));

    if (out->Buffer) {
        RtlCopyUnicodeString(out, name);
        ExFreePool(name);
        return true;
    }

    ExFreePool(name);
    return false;
}

void free_name(PUNICODE_STRING str) {
    if (str && str->Buffer) {
        ExFreePool(str->Buffer);
        str->Buffer = nullptr;
        str->Length = str->MaximumLength = 0;
    }
}

// Internal matcher against a name list

template <size_t N>
static bool match_name_list(PWCH buffer, const wchar_t* const (&list)[N]) {
    if (!buffer)
        return false;
    for (size_t i = 0; i < N; ++i) {
        if (wcsstr(buffer, list[i]))
            return true;
    }
    return false;
}

template <size_t N>
static bool match_by_pid(HANDLE pid, const wchar_t* const (&list)[N]) {
    UNICODE_STRING name{};
    if (!get_name_by_pid(pid, &name))
        return false;

    bool result = match_name_list(name.Buffer, list);
    free_name(&name);
    return result;
}

template <size_t N>
static bool match_by_eprocess(PEPROCESS process,
                              const wchar_t* const (&list)[N]) {
    UNICODE_STRING name{};
    if (!get_name_by_eprocess(process, &name))
        return false;

    bool result = match_name_list(name.Buffer, list);
    free_name(&name);
    return result;
}

// Classification queries — by PID

bool is_target(HANDLE pid) {
    return match_by_pid(pid, names::target);
}
bool is_hidden(HANDLE pid) {
    return match_by_pid(pid, names::hidden);
}
bool is_monitored(HANDLE pid) {
    return match_by_pid(pid, names::monitored);
}

// Classification queries — by PEPROCESS

bool is_target(PEPROCESS process) {
    return match_by_eprocess(process, names::target);
}
bool is_hidden(PEPROCESS process) {
    return match_by_eprocess(process, names::hidden);
}
bool is_monitored(PEPROCESS process) {
    return match_by_eprocess(process, names::monitored);
}

// Classification queries — by raw name buffer

bool is_target(PWCH buffer) {
    return match_name_list(buffer, names::target);
}
bool is_hidden(PWCH buffer) {
    return match_name_list(buffer, names::hidden);
}
bool is_monitored(PWCH buffer) {
    return match_name_list(buffer, names::monitored);
}

}  // namespace process_manager
