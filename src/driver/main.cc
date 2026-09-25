#include <ntifs.h>
#include <wdmsec.h>

#include "session.hpp"
namespace {
PDEVICE_OBJECT device{};
UNICODE_STRING link = RTL_CONSTANT_STRING(L"\\DosDevices\\BlookDrv");
bool linked{};
const GUID device_class{0xb15954f0,
                        0x5889,
                        0x4d19,
                        {0x98, 0x11, 0x2c, 0xcf, 0xbe, 0xf8, 0x22, 0x42}};
// Device ACL. SYSTEM and Administrators always get full access. The optional
// service-key value `AllowUsers` (REG_DWORD, default 0 - written by
// `blook-loader apply`) additionally lets *interactive* users open the device,
// so an unelevated tool can drive it. The device is the only gate, so this is a
// deliberate trade-off: every process of the logged-on user can then install
// hooks and toggle the profile. See blook.ini.
bool allow_users() {
    UNICODE_STRING path = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\BlookDrv");
    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr,
                               nullptr);
    HANDLE key{};
    if (!NT_SUCCESS(ZwOpenKey(&key, KEY_QUERY_VALUE, &attributes)))
        return false;
    struct {
        KEY_VALUE_PARTIAL_INFORMATION information;
        uint8_t data[64];
    } buffer{};
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"AllowUsers");
    ULONG length{};
    const auto status = ZwQueryValueKey(key, &name, KeyValuePartialInformation,
                                        &buffer, sizeof(buffer), &length);
    ZwClose(key);
    if (!NT_SUCCESS(status) || buffer.information.Type != REG_DWORD ||
        buffer.information.DataLength < sizeof(uint32_t))
        return false;
    return *reinterpret_cast<const uint32_t*>(buffer.information.Data) != 0;
}
NTSTATUS complete(PIRP irp, NTSTATUS status) {
    irp->IoStatus.Status = status;
    if (!NT_SUCCESS(status))
        irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}
NTSTATUS dispatch(PDEVICE_OBJECT, PIRP irp) {
    irp->IoStatus.Information = 0;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return complete(irp, STATUS_INVALID_DEVICE_STATE);
    auto stack = IoGetCurrentIrpStackLocation(irp);
    switch (stack->MajorFunction) {
        case IRP_MJ_CREATE:
            return complete(irp, blook::open_session(irp, stack->FileObject));
        case IRP_MJ_CLEANUP:
            blook::cleanup_session(stack->FileObject);
            return complete(irp, STATUS_SUCCESS);
        case IRP_MJ_CLOSE:
            blook::close_session(stack->FileObject);
            return complete(irp, STATUS_SUCCESS);
        case IRP_MJ_DEVICE_CONTROL:
            return complete(irp, blook::control_session(irp, stack));
        default:
            return complete(irp, STATUS_INVALID_DEVICE_REQUEST);
    }
}
void cleanup() {
    if (linked) {
        IoDeleteSymbolicLink(&link);
        linked = false;
    }
    blook::shutdown_sessions();
    if (device) {
        IoDeleteDevice(device);
        device = nullptr;
    }
}
void unload(PDRIVER_OBJECT) {
    cleanup();
}
}  // namespace
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING) {
    driver->DriverUnload = unload;
    for (auto& handler : driver->MajorFunction)
        handler = dispatch;
    auto status = blook::initialize_sessions();
    if (!NT_SUCCESS(status))
        return status;
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Device\\BlookDrv");
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    if (allow_users())
        sddl = RTL_CONSTANT_STRING(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)");
    status = IoCreateDeviceSecure(driver, 0, &name, FILE_DEVICE_UNKNOWN,
                                  FILE_DEVICE_SECURE_OPEN, FALSE, &sddl,
                                  &device_class, &device);
    if (!NT_SUCCESS(status)) {
        cleanup();
        return status;
    }
    status = IoCreateSymbolicLink(&link, &name);
    if (!NT_SUCCESS(status)) {
        cleanup();
        return status;
    }
    linked = true;
    device->Flags |= DO_BUFFERED_IO;
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
