# Overview

- This Proof-of-Concept corresponds to our Bring Your Own Vulnerable Driver (BYOVD) research.
- The process termination vulnerability has been reported to the vendor via responsible disclosure prior to publication.
- The vendor was highly responsive and engaged technically with our team. Adlice had a kernel driver named `TrueSight.sys`, with version `3.4.0`, that was being [exploited in the wild](https://thehackernews.com/2025/02/2500-truesightsys-driver-variants.html) in February of 2025. They the `TrueSight.sys` driver to `RootLaser.sys` and bumped up the version to `3.4.1`. They implemented an SDDL (`L"VX"`) to restrict handle cration to Administrator/SYSTEM, mitigating LPE. They also implemented a PPL check that successfully blocks terminating protected processes (like `defender` or `csrss`) by returning a `ERROR_NOT_SUPPORTED`. We have verified these mitigations are effective against the primary goals of a BYOVD campaign.
- We are publishing this PoC for educational purposes and to advance kernel security research. While the Process Kill IOCTL is restricted against PPL processes, it can still terminate non-protected processes from Rin0. Additionally, the driver contains additional findings, consisting of an Arbitrary Kernel Read and a Driver Information Leak, that we will leave as an exercise for the community to explore. 

**Affected versions (as tested):**  
- Version [3.4.1] - SHA-256: `85b69f4e518c66b8ba7154ecb1ac1e8791dfe2fdf1e20b7c3a707f59639ac10d`
    > *Note: Earlier versions of TrueSight may lack the SDDL and PPL mitigations present in 3.4.1*

**Tested on Windows 10 x64 build:**
- Version 22H2 (OS Build 19045.2006).

## Proof of Concept
Compile the PoC code with the x64 Visual Studio Developer Command Prompt by running the command `cl poc.c`.

Install the vulnerable driver with the following commands in a command-line with Administrator privileges:

```bash
> sc.exe create RootLaser type=kernel binPath=C:\Path\To\Driver\RootLaser.sys
> sc.exe start RootLaset
```

Once installed, ensure you are in an **Administrator** command prompt, and run the compiled PoC to connect to the driver and test the IOCTLs.
