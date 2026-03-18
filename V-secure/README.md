# Overview

- This Proof-of-Concept corresponds to our Bring Your Own Vulnerable Driver (BYOVD) research.
- The process termination vulnerability involves a functional, unauthenticated IOCTL (**0x22CEF0**) within the `ZYArKit.sys` driver that allows an administrator to terminate arbitrary non-protected processes.
- The driver initializes by creating `\\Device\\ZyArk` and a symbolic link `\\DosDevices\\ZyArk`. The main dispatcher function (`sub_118D0`) filters for `IRP_MJ_DEVICE_CONTROL` and the IOCTL sub-dispatcher (`sub_1159C`) performs a table lookup comparing the user-provided IOCTL against a list at `unk_1FD80`. When IOCTL **0x22CEF0** is called, the driver validates an input buffer size of **2108**, extracts a process handle at offset **2096**, references the object via `ObReferenceObjectByHandle`, and invokes `sub_1AF14`, which executes `ZwTerminateProcess`.
- We are publishing this PoC for educational purposes and to advance kernel security research. While the driver utilizes `WdmlibIoCreateDeviceSecure` with an SDDL string to manage access, it can still terminate non-protected processes from Ring 0.

**Affected versions (as tested):**
- Version [2.0.13.5] - SHA-256: `46883bc25c77678f60c1b836f4c438d87158c9af6b229f533522f635a0d5276e`  
    > *Note: Signed on 2017-05-02 by Beijing chenxinlingchuang Information Technology CO.,Ltd.*

**Tested on Windows 10 x64 build:**
- Version 22H2 (OS Build 19045.2006).

## Proof of Concept
Compile the PoC code with the x64 Visual Studio Developer Command Prompt by running the command `cl poc.c`.

Install the vulnerable driver with the following commands in a command-line with Administrator privileges:

```bash
> sc.exe create ZYArKit type=kernel binPath=C:\Path\To\Driver\ZYArKit.sys
> sc.exe start ZYArKit
```

Once installed, ensure you are in an **Administrator** command prompt, and run the compiled PoC to connect to the driver and test the IOCTLs.
