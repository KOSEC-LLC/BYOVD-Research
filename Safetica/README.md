# Overview

- This Proof-of-Concept corresponds to the vulnerability detailed in the KOSEC blog [SAFETICA Kernel Privilege Bypass Vulnerability](http://www.kosec.io/2025/11/01/safetica-byovd.html)
- The vulnerability has been reported through CERT prior to publication

**Affected versions (as tested):**  
- Version [11.11.4.0] - SHA-256: `70bcec00c215fe52779700f74e9bd669ff836f594df92381cbfb7ee0568e7a8b`  
- Version [10.5.75.0] - SHA-256: `85d21ad0e0b43d122f3c9ec06036b08398635860c93d764f72fb550fb44cf786`

**Tested on Windows 10 x64 build:**
- Version 1903 (OS Build 18362.30)
- Version 22H2 (OS Build 19045.2006).
## Proof of Concept
Compile the PoC code with the x64 Visual Studio Developer Command Prompt by running the command `cl poc.c`.

Install the vulnerable driver with the following commands in a command-line with Administrator privileges:
```bash
> sc.exe create STProcessMonitor type=kernel binPath=C:\Path\To\Driver\ProcessMonitorDriver.sys
> sc.exe start STProcessMonitor
```

Once installed, you can run the compiled PoC to connect to the malicious driver and exploit the vulnerability.

## Download
To get this vulnerable driver from "the wild"
- Run the installer and download the `safetica_endpoint_client_x64` (SHA256: `9dbc82d61c0759c4db9862acd63408abd4664cd698b9d5669f9558a544133e3b`)
  - At the bottom of the Safetica ONE installer, clicke where it says "Optional: Safetica Client"
  - The vulnerable driver is installed under `C:\Program Files\Safetica\` as `ProcessMonitorDriver.sys`