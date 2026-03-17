# Overview
- This is an older driver that was recently exploited in a BYOVD campaign detailed here: https://www.bleepingcomputer.com/news/security/edr-killer-tool-uses-signed-kernel-driver-from-forensic-software/
- The exploit path is as follows:
    1. The attacker's program runs as admin and gets its own Process ID using `GetCurrentProcessId()`
    1. It constructs a 16-byte buffer for the `KillProc` IOCTL (`0x223078`)
    1. It writes its own PID into th efirst 8 bytes of the buffer
    1. It writes the target's PID into the second 8 bytes of the buffer
    1. It calls `DeviceIoControl`
    1. The driver's validation function receives the buffer and compares the first 8 bytes of the caller's PID to see if the check passes
    1. The dispatcher then calls `KillProc`, which reads the target's PID from the second 8 bytes and terminates the process

**Affected versions (as tested):**  
- Version [EnCase Driver for WinNET 64 bit Svn Rev:98733 with EnCase 7.9.6.3] - SHA-256: `d42f1b420747b82533e33107c710c45c29ff20aa5da3d1c8498b7bed7f9ebc81`

**Tested on Windows 10 x64 build:**
- Version 22H2 (OS Build 19045.2006).

## Proof of Concept
Compile the PoC code with the x64 Visual Studio Developer Command Prompt by running the command `cl poc.c`.

Install the vulnerable driver with the following commands in a command-line with Administrator privileges:
```bash
> sc.exe create EnPortv type=kernel binPath=C:\Path\To\Driver\EnPortv.sys
> sc.exe start EnPortv
```

Once installed, ensure you are in an **Administrator** command prompt, and run the compiled PoC to connect to the driver and test the IOCTLs.