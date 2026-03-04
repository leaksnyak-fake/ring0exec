# ring0exec

> ❗ **Disclaimer**
> This project is provided **strictly for educational and research purposes only.**
> The author bears **no responsibility** for any direct or indirect damages, illegal activity,
> or misuse resulting from the use of this code.
> By cloning or using this repository you acknowledge that you have read and agreed to these terms.

---

![Platform](https://img.shields.io/badge/platform-Windows%2011%20x64-0078D4)
![Language](https://img.shields.io/badge/language-C%20%28ANSI%29-lightgrey)
![WDK](https://img.shields.io/badge/WDK-10.0-blue)
![Arch](https://img.shields.io/badge/arch-x64%20only-important)

Windows kernel-mode driver that spawns a native Win32 process entirely from ring-0 using `NtCreateUserProcess` resolved dynamically through the SSDT — without any user-mode launcher or hardcoded kernel offsets.

> ⚠️ Requires test-signing mode (`bcdedit /set testsigning on`) or a kernel debugger attached with DSE bypass.

---

## How it works

Standard WDK process-creation APIs either require a kernel-accessible image or don't produce a full Win32 process. This driver takes a lower-level approach:

**1. SSDT resolution**  
Reads the `LSTAR` MSR (`0xC0000082`) to get the address of `KiSystemCall64`, then scans its prologue for the `LEA R10, [KiServiceTable]` encoding (`4C 8D 15 <rel32>`) to locate `KeServiceDescriptorTable` at runtime — no hardcoded offsets, no symbol lookups.

**2. Syscall index extraction**  
`ntdll.dll` is mapped into the current address space via `ZwCreateSection` / `ZwMapViewOfSection`. The export table is walked to find each `Nt*` stub, and the syscall index is extracted from the stub bytes using two strategies in order:
- *Semi-hardcoded scan* — scans forward for `MOV EAX, imm32` (tolerates hook trampolines)
- *Hardcoded pattern* — matches the canonical `4C 8B D1 B8 XX XX 00 00` prologue as fallback

**3. Process parameters**  
`RtlCreateProcessParametersEx` is reimplemented in kernel mode. It allocates a single paged-pool block containing the `RTL_USER_PROCESS_PARAMETERS` header, all string data, and the environment block in the exact layout the kernel expects. The environment is captured from the first session-1 process found via `NtReadVirtualMemory`, so the spawned process gets a proper `PATH`, locale, and user variables.

**4. Process creation**  
`NtCreateUserProcess` is called with `THREAD_CREATE_FLAGS_CREATE_SUSPENDED`. Before resume: the driver reads the PE headers from the new process's virtual memory to resolve the entry point, then clears `PEB->BeingDebugged` and `PEB->NtGlobalFlag` via `NtWriteVirtualMemory`.

---

## Demo

### Kernel debug output (WinDbg)

![WinDbg log](screenshots/windbg.png)

Full resolution of what happened:
- `KiSystemCall64` found at `FFFFF8039F0BD740` via LSTAR MSR scan
- SSDT located at `FFFFF8039FC018C0`, limit 489 entries
- `ntdll.dll` mapped at `00007FFB516E0000`
- All 5 syscall indices resolved via semi-hardcoded scan (offset 3 — canonical unpatched stubs):

| Function | Index | Kernel address |
|---|---|---|
| `NtCreateUserProcess` | `0xD1` | `FFFFF8039F4C7440` |
| `NtResumeThread` | `0x52` | `FFFFF8039F40FAE0` |
| `NtQueryInformationProcess` | `0x19` | `FFFFF8039F3B3730` |
| `NtWriteVirtualMemory` | `0x3A` | `FFFFF8039F3B15B0` |
| `NtReadVirtualMemory` | `0x3F` | `FFFFF8039F3B15E0` |

- Environment copied from PID 540 (session-1), 2840 bytes
- `NtCreateUserProcess` → `State=6` (`PsCreateSuccess`)
- Entry point resolved: `00007FF70D077C70` (RVA `0x27C70`)
- PEB patched: `BeingDebugged = 0`, `NtGlobalFlag = 0`
- Process running as PID **2684**

---

### Process Hacker — process tree

`cmd.exe` (PID 2684) visible as a direct child of `System (4)`:

![Process list](screenshots/prochacker.png)

---

### General tab — parent process anomaly

`Parent: System (4)` — a user-mode Win32 process with System as parent is the clearest indicator of kernel-originated creation:

![General tab](screenshots/general.png)

---

### Environment tab

Environment block captured from a session-1 process and passed through `RTL_USER_PROCESS_PARAMETERS`. `USERNAME: SYSTEM`, `Path`, `SystemRoot` all present:

![Environment tab](screenshots/env.png)

---

### Token tab

Running as `NT AUTHORITY\СИСТЕМА` in session 0:

![Token tab](screenshots/token.png)

---

## Requirements

- Windows 10 / 11 x64
- Visual Studio 2019 or 2022
- WDK 10.0 (matched to your SDK version)
- Test-signing enabled **or** kernel debugger attached

---

## Building

1. Open `ring0exec.sln`
2. Select **Release / x64**
3. Build → `x64\Release\ring0exec.sys`

No external dependencies. All undocumented structures are defined locally in `ntoskrnl.h`.

---

## Loading

```bat
bcdedit /set testsigning on
:: reboot required

sc create kproc type= kernel binPath= C:\path\to\ring0exec.sys
sc start kproc

sc stop kproc
sc delete kproc
```

Attach **DebugView** (kernel capture enabled) or a WinDbg session to see the full resolution log.

---

## Project structure

```
├── ring0exec/
│   ├── main.c                            # DriverEntry, Unload, global NT API pointers
│   ├── exec.c / exec.h                   # Process creation, parameter building, PEB patching
│   ├── utils.c / utils.h                 # SSDT scan, ntdll mapping, export lookup, index extraction
│   ├── ntoskrnl.h                        # Undocumented NT structures (RTL_USER_PROCESS_PARAMETERS, PS_CREATE_INFO, SDT ...)
│   ├── _def.h                            # NT API typedefs and extern declarations
│   ├── ring0exec.inf
│   ├── ring0exec.vcxproj
│   └── ring0exec.vcxproj.filters
├── screenshots/
│   ├── windbg.png
│   ├── prochacker.png
│   ├── general.png
│   ├── env.png
│   └── token.png
├── .gitignore
├── .gitattributes
├── LICENSE.txt
├── ring0exec.sln
└── README.md
```

---

## License

MIT
