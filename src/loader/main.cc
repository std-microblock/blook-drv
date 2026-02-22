#include <windows.h>

#include <cstdio>
#include <string>

#include "ipc/protocol.hpp"

// Service and driver management
class DriverService {
   public:
    DriverService(const wchar_t* service_name, const wchar_t* driver_path)
        : service_name_(service_name),
          driver_path_(driver_path),
          scm_(nullptr),
          service_(nullptr) {}

    ~DriverService() { close(); }

    bool create_and_start() {
        scm_ = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scm_) {
            printf("Failed to open SCM: %lu\n", GetLastError());
            return false;
        }

        // Try to open existing service first
        service_ = OpenServiceW(scm_, service_name_, SERVICE_ALL_ACCESS);

        if (!service_) {
            // Create new service
            service_ = CreateServiceW(
                scm_, service_name_, service_name_, SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL, driver_path_, nullptr, nullptr, nullptr,
                nullptr, nullptr);

            if (!service_) {
                printf("Failed to create service: %lu\n", GetLastError());
                CloseServiceHandle(scm_);
                scm_ = nullptr;
                return false;
            }
            printf("Service created.\n");
        } else {
            printf("Service already exists.\n");
        }

        // Start the service
        if (!StartServiceW(service_, 0, nullptr)) {
            DWORD error = GetLastError();
            if (error != ERROR_SERVICE_ALREADY_RUNNING) {
                printf("Failed to start service: %lu\n", error);
                return false;
            }
            printf("Service already running.\n");
        } else {
            printf("Service started.\n");
        }

        return true;
    }

    bool stop_and_delete() {
        if (service_) {
            // Stop the service
            SERVICE_STATUS status;
            if (ControlService(service_, SERVICE_CONTROL_STOP, &status)) {
                printf("Service stopped.\n");
                // Wait for service to stop
                Sleep(1000);
            }

            // Delete the service
            if (DeleteService(service_)) {
                printf("Service deleted.\n");
            } else {
                DWORD error = GetLastError();
                if (error != ERROR_SERVICE_MARKED_FOR_DELETE) {
                    printf("Failed to delete service: %lu\n", error);
                }
            }

            CloseServiceHandle(service_);
            service_ = nullptr;
        }

        if (scm_) {
            CloseServiceHandle(scm_);
            scm_ = nullptr;
        }

        return true;
    }

   private:
    void close() {
        if (service_) {
            CloseServiceHandle(service_);
            service_ = nullptr;
        }
        if (scm_) {
            CloseServiceHandle(scm_);
            scm_ = nullptr;
        }
    }

    const wchar_t* service_name_;
    const wchar_t* driver_path_;
    SC_HANDLE scm_;
    SC_HANDLE service_;
};

// IPC Client
class IpcClient {
   public:
    IpcClient() : device_(INVALID_HANDLE_VALUE) {}

    ~IpcClient() { close(); }

    bool connect() {
        device_ =
            CreateFileW(ipc::kUserModePath, GENERIC_READ | GENERIC_WRITE, 0,
                        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (device_ == INVALID_HANDLE_VALUE) {
            printf("Failed to connect to driver: %lu\n", GetLastError());
            return false;
        }

        return true;
    }

    void close() {
        if (device_ != INVALID_HANDLE_VALUE) {
            CloseHandle(device_);
            device_ = INVALID_HANDLE_VALUE;
        }
    }

    bool ping() {
        if (device_ == INVALID_HANDLE_VALUE) {
            return false;
        }

        ipc::PingRequest request{};
        request.magic = ipc::PingRequest::kMagic;

        ipc::PingResponse response{};
        DWORD bytes_returned = 0;

        BOOL result = DeviceIoControl(
            device_, ipc::IOCTL_BLOOK_PING, &request, sizeof(request),
            &response, sizeof(response), &bytes_returned, nullptr);

        if (!result) {
            printf("Ping failed: %lu\n", GetLastError());
            return false;
        }

        if (response.magic != ipc::PingResponse::kMagic) {
            printf("Invalid ping response magic\n");
            return false;
        }

        if (response.status != ipc::PingResponse::kStatusOk) {
            printf("Ping returned error status: %lu\n", response.status);
            return false;
        }

        return true;
    }

    bool get_version(ipc::VersionInfo& version) {
        if (device_ == INVALID_HANDLE_VALUE) {
            return false;
        }

        DWORD bytes_returned = 0;

        BOOL result = DeviceIoControl(device_, ipc::IOCTL_BLOOK_GET_VERSION,
                                      nullptr, 0, &version, sizeof(version),
                                      &bytes_returned, nullptr);

        if (!result) {
            printf("Get version failed: %lu\n", GetLastError());
            return false;
        }

        return true;
    }

   private:
    HANDLE device_;
};

// Get driver path relative to executable
std::wstring get_driver_path() {
    wchar_t exe_path[MAX_PATH];
    GetModuleFileNameW(nullptr, exe_path, MAX_PATH);

    // Find last backslash
    wchar_t* last_slash = wcsrchr(exe_path, L'\\');
    if (last_slash) {
        *(last_slash + 1) = L'\0';
    }

    return std::wstring(exe_path) + L"blook-drv.sys";
}

void print_usage() {
    printf("BlookLoader - Driver loader and IPC client\n\n");
    printf("Usage: blook-loader <command>\n\n");
    printf("Commands:\n");
    printf("  ping      - Send ping to driver\n");
    printf("  version   - Get driver version\n");
    printf("  help      - Show this help\n\n");
    printf(
        "The driver service is automatically started when the loader runs\n");
    printf("and stopped when the loader exits.\n");
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::wstring command = argv[1];

    if (command == L"help" || command == L"-h" || command == L"--help") {
        print_usage();
        return 0;
    }

    // Get driver path
    std::wstring driver_path = get_driver_path();
    printf("Driver path: %ls\n", driver_path.c_str());

    // Create and start service
    DriverService service(L"BlookDrv", driver_path.c_str());
    if (!service.create_and_start()) {
        printf("Failed to start driver service.\n");
        return 1;
    }

    // Connect to driver
    IpcClient client;
    if (!client.connect()) {
        printf("Failed to connect to driver.\n");
        service.stop_and_delete();
        return 1;
    }

    int result = 0;

    // Execute command
    if (command == L"ping") {
        printf("Sending ping...\n");
        if (client.ping()) {
            printf("Pong! Driver is responsive.\n");
        } else {
            printf("Ping failed.\n");
            result = 1;
        }
    } else if (command == L"version") {
        ipc::VersionInfo version;
        if (client.get_version(version)) {
            printf("Driver version: %u.%u.%u\n", version.major, version.minor,
                   version.patch);
        } else {
            printf("Failed to get version.\n");
            result = 1;
        }
    } else {
        printf("Unknown command: %ls\n", command.c_str());
        print_usage();
        result = 1;
    }

    // Cleanup
    client.close();
    service.stop_and_delete();

    return result;
}
