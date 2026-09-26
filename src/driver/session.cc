#include "session.hpp"

#include <ntifs.h>
#include <intrin.h>

#include "driver/hide/hide.hpp"
#include "driver/hooks.hpp"
#include "driver/hv/hv.h"
#include "driver/resources.hpp"

namespace blook {
namespace {
struct session {
    LIST_ENTRY link{};
    PEPROCESS process{};
    uint32_t pid{};
    uint64_t token{};
    bool enabled{}, closed{}, exited{};
};

struct state {
    EX_PUSH_LOCK lock{};
    LIST_ENTRY sessions{};
    unsigned session_count{};
    void* power_callback{};
    void* processor_callback{};
    bool process_callback{}, suspended{}, stopping{};
    uint64_t next_token{1};
    NTSTATUS backend_status{STATUS_DEVICE_NOT_READY};
};

state* manager{};

uint32_t pid_of(HANDLE value) {
    return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(value));
}

void revoke(session& value, bool exiting) {
    if (exiting)
        value.exited = true;
    value.enabled = false;
    // A file object owns a session, not every hook targeting its process.
    // Diagnostic handles opened beside an active SDK session must be harmless
    // to close; conversely, this session's remote-target hooks must go too.
    revoke_session(value.token);
}

void process_notify(PEPROCESS process, HANDLE, PPS_CREATE_NOTIFY_INFO info) {
    if (info)
        return;
    const auto pid = pid_of(PsGetProcessId(process));
    {
        exclusive_lock lock{manager->lock};
        for (auto link = manager->sessions.Flink; link != &manager->sessions;
             link = link->Flink) {
            auto* value = CONTAINING_RECORD(link, session, link);
            if (value->process == process)
                revoke(*value, true);
        }
    }
    // A dead PID must not stay pinned to a role or keep its hooks alive.
    revoke_process(pid);
    hide::unpin(pid);
    hide::forget_process(pid);
}

void processor_notify(void*, PKE_PROCESSOR_CHANGE_NOTIFY_CONTEXT context,
                      PNTSTATUS status) {
    // Do not silently allow an unvirtualized hot-added CPU to execute hooked
    // pages.
    if (context->State == KeProcessorAddStartNotify)
        *status = STATUS_NOT_SUPPORTED;
}

void power_notify(void*, void* argument1, void* argument2) {
    if (argument1 != reinterpret_cast<void*>(PO_CB_SYSTEM_STATE_LOCK))
        return;
    exclusive_lock lock{manager->lock};
    if (manager->stopping)
        return;
    if (!argument2) {
        hv::stop();
        manager->suspended = true;
        manager->backend_status = STATUS_DEVICE_NOT_READY;
        return;
    }
    if (!manager->suspended)
        return;
    manager->suspended = false;
    manager->backend_status = hv::start();
    if (!NT_SUCCESS(manager->backend_status))
        return;
    restore_all();
}

session* from_file(PFILE_OBJECT file) {
    return static_cast<session*>(file->FsContext);
}

NTSTATUS enable(session& value) {
    if (value.enabled)
        return STATUS_SUCCESS;
    if (!hv::ghv.running)
        return STATUS_DEVICE_NOT_READY;
    value.enabled = true;
    return STATUS_SUCCESS;
}
}  // namespace

NTSTATUS initialize_sessions() {
    manager = allocate_object<state>();
    if (!manager)
        return STATUS_INSUFFICIENT_RESOURCES;
    InitializeListHead(&manager->sessions);
    auto status = initialize_hooks();
    if (!NT_SUCCESS(status)) {
        shutdown_sessions();
        return status;
    }
    status = PsSetCreateProcessNotifyRoutineEx(process_notify, FALSE);
    if (!NT_SUCCESS(status)) {
        shutdown_sessions();
        return status;
    }
    manager->process_callback = true;
    manager->processor_callback =
        KeRegisterProcessorChangeCallback(processor_notify, nullptr, 0);
    if (!manager->processor_callback) {
        shutdown_sessions();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Callback\\PowerState");
    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &name,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               nullptr, nullptr);
    PCALLBACK_OBJECT object{};
    status = ExCreateCallback(&object, &attributes, FALSE, TRUE);
    if (!NT_SUCCESS(status)) {
        shutdown_sessions();
        return status;
    }
    manager->power_callback = ExRegisterCallback(object, power_notify, nullptr);
    ObDereferenceObject(object);
    if (!manager->power_callback) {
        shutdown_sessions();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    {
        exclusive_lock lock{manager->lock};
        manager->backend_status = hv::start();
        status = manager->backend_status;
    }
    if (!NT_SUCCESS(status))
        shutdown_sessions();
    return status;
}

void shutdown_sessions() {
    if (!manager)
        return;
    {
        exclusive_lock lock{manager->lock};
        manager->stopping = true;
    }
    // Remove the profile hooks while the hypervisor is still able to unpatch.
    hide::deactivate();
    if (manager->power_callback)
        ExUnregisterCallback(manager->power_callback);
    if (manager->process_callback)
        PsSetCreateProcessNotifyRoutineEx(process_notify, TRUE);
    // Normal driver unload is not possible while open device objects reference
    // it.
    {
        exclusive_lock lock{manager->lock};
        hv::stop();
        shutdown_hooks();
        NT_ASSERT(IsListEmpty(&manager->sessions));
    }
    if (manager->processor_callback)
        KeDeregisterProcessorChangeCallback(manager->processor_callback);
    delete_object(manager);
    manager = nullptr;
}

NTSTATUS open_session(PIRP irp, PFILE_OBJECT file) {
    if (irp->RequestorMode != UserMode || IoIs32bitProcess(irp) ||
        file->FileName.Length)
        return STATUS_ACCESS_DENIED;
    auto process = IoGetRequestorProcess(irp);
    if (!process || process != PsGetCurrentProcess())
        return STATUS_ACCESS_DENIED;
    exclusive_lock lock{manager->lock};
    if (manager->stopping || manager->session_count == 64)
        return STATUS_DEVICE_BUSY;
    // Zero and system_token are reserved; never reuse an ownership token.
    if (!manager->next_token || manager->next_token == system_token)
        return STATUS_INTEGER_OVERFLOW;
    auto* value = allocate_object<session>();
    if (!value)
        return STATUS_INSUFFICIENT_RESOURCES;
    value->process = process;
    value->pid = pid_of(PsGetProcessId(process));
    value->token = manager->next_token++;
    ObReferenceObject(process);
    InsertTailList(&manager->sessions, &value->link);
    ++manager->session_count;
    file->FsContext = value;
    return STATUS_SUCCESS;
}

void cleanup_session(PFILE_OBJECT file) {
    exclusive_lock lock{manager->lock};
    auto* value = from_file(file);
    if (value && !value->closed) {
        revoke(*value, false);
        value->closed = true;
    }
}

void close_session(PFILE_OBJECT file) {
    exclusive_lock lock{manager->lock};
    auto* value = from_file(file);
    if (!value)
        return;
    revoke(*value, false);
    RemoveEntryList(&value->link);
    --manager->session_count;
    ObDereferenceObject(value->process);
    delete_object(value);
    file->FsContext = nullptr;
}

NTSTATUS control_session(PIRP irp, PIO_STACK_LOCATION stack) {
    exclusive_lock lock{manager->lock};
    auto* value = from_file(stack->FileObject);
    if (!value || value->closed || value->exited || manager->stopping ||
        irp->RequestorMode != UserMode ||
        IoGetRequestorProcess(irp) != value->process ||
        PsGetCurrentProcess() != value->process)
        return STATUS_ACCESS_DENIED;

    const auto input = stack->Parameters.DeviceIoControl.InputBufferLength;
    const auto output = stack->Parameters.DeviceIoControl.OutputBufferLength;
    auto* buffer = irp->AssociatedIrp.SystemBuffer;
    const auto code = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (code) {
        case ipc::IOCTL_BLOOK_PING: {
            if (input != sizeof(ipc::PingRequest) ||
                output < sizeof(ipc::PingResponse))
                return STATUS_BUFFER_TOO_SMALL;
            if (static_cast<ipc::PingRequest*>(buffer)->magic !=
                ipc::PingRequest::kMagic)
                return STATUS_INVALID_PARAMETER;
            *static_cast<ipc::PingResponse*>(buffer) = {
                ipc::PingResponse::kMagic, 0};
            irp->IoStatus.Information = sizeof(ipc::PingResponse);
            return STATUS_SUCCESS;
        }
        case ipc::IOCTL_BLOOK_GET_VERSION:
            if (input || output < sizeof(ipc::VersionInfo))
                return STATUS_BUFFER_TOO_SMALL;
            *static_cast<ipc::VersionInfo*>(buffer) = ipc::kDriverVersion;
            irp->IoStatus.Information = sizeof(ipc::VersionInfo);
            return STATUS_SUCCESS;
        case ipc::IOCTL_BLOOK_QUERY: {
            if (input || output < sizeof(ipc::QueryResponse))
                return STATUS_BUFFER_TOO_SMALL;
            *static_cast<ipc::QueryResponse*>(buffer) = {
                ipc::abi_version,         hv::ghv.running ? 1u : 0u,
                value->enabled ? 1u : 0u, user_hook_count(value->pid),
                hide::active() ? 1u : 0u, ipc::abi_version,
                manager->backend_status,  hide::window_hook_count()};
            irp->IoStatus.Information = sizeof(ipc::QueryResponse);
            return STATUS_SUCCESS;
        }
        case ipc::IOCTL_BLOOK_STATS: {
            if (input || output < sizeof(ipc::StatsResponse))
                return STATUS_BUFFER_TOO_SMALL;
            auto* out = static_cast<ipc::StatsResponse*>(buffer);
            *out = {};
            out->header.version = ipc::abi_version;
            out->header.size = sizeof(ipc::StatsResponse);
            out->execute_violations = hv::g_stats.execute_violations;
            out->data_violations = hv::g_stats.data_violations;
            out->window_open = hv::g_stats.window_open;
            out->identity_ok = hv::g_stats.identity_ok;
            out->identity_mismatch = hv::g_stats.identity_mismatch;
            out->identity_failed = hv::g_stats.identity_failed;
            out->internal_entry = hv::g_stats.internal_entry;
            out->shadow_mapped = hv::g_stats.shadow_mapped;
            out->original_step = hv::g_stats.original_step;
            out->unowned_group = hv::g_stats.unowned_group;
            for (unsigned i = 0; i < ipc::stats_exit_reason_slots; ++i)
                out->exit_reasons[i] =
                    static_cast<uint64_t>(hv::g_stats.exit_reasons[i]);
            out->vcpu_count = hv::g_stats.vcpu_count;
            out->invept_calls = hv::g_stats.invept_calls;
            out->invept_error = hv::g_stats.invept_error;
            out->ept_misconfig = hv::g_stats.ept_misconfig;
            out->install_rounds = hv::g_stats.install_rounds;
            out->install_ok_cpus = hv::g_stats.install_ok_cpus;
            out->install_fail_cpus = hv::g_stats.install_fail_cpus;
            for (unsigned i = 0; i < ipc::stats_cpu_mask_words; ++i) {
                out->install_ok_mask[i] =
                    static_cast<uint64_t>(hv::g_stats.install_ok_mask[i]);
                out->install_fail_mask[i] =
                    static_cast<uint64_t>(hv::g_stats.install_fail_mask[i]);
            }
            out->armed_entries_verified = hv::g_stats.armed_entries_verified;
            out->armed_entries_wrong = hv::g_stats.armed_entries_wrong;
            for (unsigned i = 0; i < ipc::stats_hook_rows; ++i) {
                const auto& row = hv::g_hook_diag[i];
                out->hooks[i].id = static_cast<uint32_t>(row.id);
                out->hooks[i].target = static_cast<uint64_t>(row.target);
                out->hooks[i].pfn = static_cast<uint64_t>(row.pfn);
                out->hooks[i].address_space =
                    static_cast<uint64_t>(row.address_space);
                out->hooks[i].domain = static_cast<uint32_t>(row.domain);
                out->hooks[i].active = static_cast<uint32_t>(row.active);
                out->hooks[i].execute_hits =
                    static_cast<uint64_t>(row.execute_hits);
                out->hooks[i].shadow_mapped =
                    static_cast<uint64_t>(row.shadow_mapped);
                out->hooks[i].identity_mismatches =
                    static_cast<uint64_t>(row.identity_mismatches);
                if (out->hooks[i].active) ++out->hook_rows;
            }
            irp->IoStatus.Information = sizeof(ipc::StatsResponse);
            return STATUS_SUCCESS;
        }
        case ipc::IOCTL_BLOOK_PROBE: {
            if (input != sizeof(ipc::ProbeRequest) ||
                output < sizeof(ipc::ProbeResponse))
                return STATUS_INFO_LENGTH_MISMATCH;
            // METHOD_BUFFERED hands the driver ONE buffer that is both the
            // input and the output, so the request has to be copied out before
            // anything is written back - writing the response first clobbers
            // the address that was asked about.
            auto* out = static_cast<ipc::ProbeResponse*>(buffer);
            const uint64_t address =
                reinterpret_cast<ipc::ProbeRequest*>(buffer)->address;
            out->header.version = ipc::abi_version;
            out->header.size = sizeof(ipc::ProbeResponse);
            out->cr3 = __readcr3();
            out->physical =
                MmGetPhysicalAddress(reinterpret_cast<void*>(address)).QuadPart;
            out->pid =
                reinterpret_cast<uint64_t>(PsGetCurrentProcessId());
            out->peb = reinterpret_cast<uint64_t>(
                PsGetProcessPeb(PsGetCurrentProcess()));
            out->kernel_physical =
                MmGetPhysicalAddress(&hv::g_stats).QuadPart;
            {
                blook::page_lock lock;
                const auto status =
                    lock.acquire(reinterpret_cast<void*>(address), UserMode,
                                 IoReadAccess);
                out->locked_status =
                    static_cast<uint64_t>(static_cast<uint32_t>(status));
                out->locked_pfn = NT_SUCCESS(status) ? lock.pfn() : 0;
            }
            irp->IoStatus.Information = sizeof(ipc::ProbeResponse);
            return STATUS_SUCCESS;
        }
        case ipc::IOCTL_BLOOK_ENABLE:
            if (input != sizeof(ipc::EnableRequest) || output)
                return STATUS_INFO_LENGTH_MISMATCH;
            if (!ipc::valid_header(*static_cast<ipc::EnableRequest*>(buffer)))
                return STATUS_REVISION_MISMATCH;
            return enable(*value);
        case ipc::IOCTL_BLOOK_INSTALL: {
            if (!value->enabled)
                return STATUS_ACCESS_DENIED;
            if (input != sizeof(ipc::InstallRequest) ||
                output < sizeof(ipc::InstallResponse))
                return STATUS_BUFFER_TOO_SMALL;
            const auto request = *static_cast<ipc::InstallRequest*>(buffer);
            if (!ipc::valid_header(request) || request.reserved)
                return STATUS_INVALID_PARAMETER;
            if (!request.length || request.length > sizeof(request.bytes))
                return STATUS_INVALID_PARAMETER;
            // pid 0 means "the calling process". A kernel target is only
            // reachable from inside the driver, never through this ABI.
            const auto target_pid = request.pid ? request.pid : value->pid;
            uint64_t id{};
            auto status = install_hook(target_pid, value->token,
                                       reinterpret_cast<void*>(request.target),
                                       request.bytes, request.length, id);
            if (NT_SUCCESS(status)) {
                *static_cast<ipc::InstallResponse*>(buffer) = {id};
                irp->IoStatus.Information = sizeof(ipc::InstallResponse);
            }
            return status;
        }
        case ipc::IOCTL_BLOOK_REMOVE:
        case ipc::IOCTL_BLOOK_REFRESH: {
            if (!value->enabled)
                return STATUS_ACCESS_DENIED;
            if (input != sizeof(ipc::HookRequest) || output)
                return STATUS_INFO_LENGTH_MISMATCH;
            const auto request = *static_cast<ipc::HookRequest*>(buffer);
            if (!ipc::valid_header(request) || !request.id)
                return STATUS_INVALID_PARAMETER;
            return code == ipc::IOCTL_BLOOK_REMOVE
                       ? remove_owned_hook(request.id, value->token)
                       : refresh_owned_hook(request.id, value->token);
        }
        case ipc::IOCTL_BLOOK_HIDE: {
            if (!value->enabled)
                return STATUS_ACCESS_DENIED;
            if (input != sizeof(ipc::HideRequest) || output)
                return STATUS_INFO_LENGTH_MISMATCH;
            const auto request = *static_cast<ipc::HideRequest*>(buffer);
            if (!ipc::valid_header(request))
                return STATUS_REVISION_MISMATCH;
            switch (request.enable_hide) {
                case 0:
                    hide::deactivate();
                    return STATUS_SUCCESS;
                case 1:
                    return hide::activate();
                case 2:
                    if (request.role != ipc::hide_role_tool &&
                        request.role != ipc::hide_role_target)
                        return STATUS_INVALID_PARAMETER;
                    hide::pin(request.pid ? request.pid : value->pid,
                              request.role == ipc::hide_role_tool
                                  ? role::tool
                                  : role::target);
                    return STATUS_SUCCESS;
                case 3:
                    hide::unpin(request.pid ? request.pid : value->pid);
                    return STATUS_SUCCESS;
                case ipc::hide_windows_on:
                    return hide::enable_windows(true);
                case ipc::hide_windows_off:
                    return hide::enable_windows(false);
                default:
                    return STATUS_INVALID_PARAMETER;
            }
        }
        case ipc::IOCTL_BLOOK_SCRUB: {
            if (!value->enabled)
                return STATUS_ACCESS_DENIED;
            if (input != sizeof(ipc::ScrubRequest) || output)
                return STATUS_INFO_LENGTH_MISMATCH;
            const auto request = *static_cast<ipc::ScrubRequest*>(buffer);
            if (!ipc::valid_header(request))
                return STATUS_REVISION_MISMATCH;
            return hide::scrub(request.pid ? request.pid : value->pid,
                               request.flags ? request.flags : ipc::scrub_all);
        }
        default:
            return STATUS_INVALID_DEVICE_REQUEST;
    }
}
}  // namespace blook
