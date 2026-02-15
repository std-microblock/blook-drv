#include <ntifs.h>
#include <windef.h>

#include "core/core.hpp"
#include "ipc/protocol.hpp"
#include "ssdt/ssdt.hpp"


//
// Driver globals
//
PDEVICE_OBJECT g_device_object = nullptr;
UNICODE_STRING g_device_name = {};
UNICODE_STRING g_symbolic_link = {};
bool g_symbolic_link_created = false;

//
// Forward declarations
//
DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DispatchCreate;
DRIVER_DISPATCH DispatchClose;
DRIVER_DISPATCH DispatchDeviceControl;

//
// IPC dispatch handlers
//
NTSTATUS HandlePing(PIRP irp, PIO_STACK_LOCATION stack) {
    UNREFERENCED_PARAMETER(stack);

    auto* input =
        static_cast<ipc::PingRequest*>(irp->AssociatedIrp.SystemBuffer);
    auto* output =
        static_cast<ipc::PingResponse*>(irp->AssociatedIrp.SystemBuffer);

    if (input->magic != ipc::PingRequest::kMagic) {
        return STATUS_INVALID_PARAMETER;
    }

    output->magic = ipc::PingResponse::kMagic;
    output->status = ipc::PingResponse::kStatusOk;

    irp->IoStatus.Information = sizeof(ipc::PingResponse);
    return STATUS_SUCCESS;
}

NTSTATUS HandleGetVersion(PIRP irp, PIO_STACK_LOCATION stack) {
    UNREFERENCED_PARAMETER(stack);

    auto* output =
        static_cast<ipc::VersionInfo*>(irp->AssociatedIrp.SystemBuffer);
    *output = ipc::kDriverVersion;

    irp->IoStatus.Information = sizeof(ipc::VersionInfo);
    return STATUS_SUCCESS;
}

//
// Dispatch routines
//
NTSTATUS DispatchCreate(PDEVICE_OBJECT device, PIRP irp) {
    UNREFERENCED_PARAMETER(device);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT device, PIRP irp) {
    UNREFERENCED_PARAMETER(device);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT device, PIRP irp) {
    UNREFERENCED_PARAMETER(device);

    auto* stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
        case ipc::IOCTL_BLOOK_PING:
            status = HandlePing(irp, stack);
            break;

        case ipc::IOCTL_BLOOK_GET_VERSION:
            status = HandleGetVersion(irp, stack);
            break;

        default:
            irp->IoStatus.Information = 0;
            break;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return status;
}

//
// Cleanup routine
//
void Cleanup() {
    // Unhook all SSDT hooks
    auto& manager = ssdt::SsdtHookManager::instance();
    if (manager.is_initialized()) {
        manager.unhook_all();
    }

    // Delete symbolic link
    if (g_symbolic_link_created) {
        IoDeleteSymbolicLink(&g_symbolic_link);
        g_symbolic_link_created = false;
    }

    // Delete device object
    if (g_device_object) {
        IoDeleteDevice(g_device_object);
        g_device_object = nullptr;
    }
}

//
// Driver unload
//
void DriverUnload(PDRIVER_OBJECT driver) {
    UNREFERENCED_PARAMETER(driver);

    log("Driver unloading...");
    Cleanup();
    log("Driver unloaded.");
}

//
// Driver entry
//
EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driver,
                              PUNICODE_STRING registry_path) {
    UNREFERENCED_PARAMETER(registry_path);

    log("BlookDrv loading...");

    NTSTATUS status;

    // Setup driver unload
    if (driver) {
        driver->DriverUnload = DriverUnload;
        driver->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
        driver->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
        driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    }

    // Create device
    RtlInitUnicodeString(&g_device_name, ipc::kDeviceName);
    status = IoCreateDevice(driver, 0, &g_device_name, FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN, FALSE, &g_device_object);

    if (!NT_SUCCESS(status)) {
        log("Failed to create device: 0x%08X", status);
        return status;
    }

    // Create symbolic link
    RtlInitUnicodeString(&g_symbolic_link, ipc::kSymbolicLink);
    status = IoCreateSymbolicLink(&g_symbolic_link, &g_device_name);

    if (!NT_SUCCESS(status)) {
        log("Failed to create symbolic link: 0x%08X", status);
        Cleanup();
        return status;
    }
    g_symbolic_link_created = true;

    // Initialize SSDT hook manager
    auto& manager = ssdt::SsdtHookManager::instance();
    auto init_result = manager.initialize();

    if (!init_result) {
        log("Failed to initialize SSDT hook manager: %s",
            core::error_to_string(init_result.error()));
        Cleanup();
        return STATUS_UNSUCCESSFUL;
    }

    log("BlookDrv loaded successfully. SSDT count: %u, Shadow SSDT count: %u",
        manager.get_ssdt_count(), manager.get_shadow_ssdt_count());

    return STATUS_SUCCESS;
}
