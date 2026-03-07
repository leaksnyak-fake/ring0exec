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

**3. Environment block capture from csrss.exe**  
A process created from ring-0 has no inherited environment. The driver solves this by stealing a complete environment block from `csrss.exe` running in session 1:

1. `ZwQuerySystemInformation(SystemProcessInformation)` snapshots the full process list into a non-paged pool buffer.
2. The snapshot is walked entry by entry, comparing `ImageName` against `L"csrss.exe"` (case-insensitive) and checking `SessionId == 1`.  `csrss.exe` is chosen because it is guaranteed to exist in every interactive session and maintains a complete, stable environment block with `PATH`, `SystemRoot`, locale, and user profile variables — unlike most user processes, it never terminates and its environment is never modified.
3. Once the target PID is found, the driver opens it with `PROCESS_VM_READ | PROCESS_QUERY_INFORMATION` via `ObOpenObjectByPointer`, reads `PEB → ProcessParameters → Environment` through a chain of `NtReadVirtualMemory` calls.
4. Because the environment size is unknown, the driver scans the remote memory in 4 KB chunks looking for the double-null terminator (`L"\0\0"`) that marks the end of the block (up to 256 KB limit).
5. Once the size is determined, the entire block is copied into a paged kernel pool allocation and passed to `MyRtlCreateProcessParametersEx`, which embeds it into the `RTL_USER_PROCESS_PARAMETERS` layout expected by `NtCreateUserProcess`.

The result: the spawned process inherits a fully populated environment indistinguishable from one set up by the session manager.

**4. Process parameters**  
`RtlCreateProcessParametersEx` is reimplemented in kernel mode. It allocates a single paged-pool block containing the `RTL_USER_PROCESS_PARAMETERS` header, all string data, and the captured environment block in the exact layout the kernel expects.

**5. Process creation**  
`NtCreateUserProcess` is called with `THREAD_CREATE_FLAGS_CREATE_SUSPENDED`. Before resume: the driver reads the PE headers from the new process's virtual memory to resolve the entry point, then clears `PEB->BeingDebugged` and `PEB->NtGlobalFlag` via `NtWriteVirtualMemory`.

**6. Critical process flag**  
After PEB patching, the driver calls `NtSetInformationProcess` with `ProcessBreakOnTermination` to mark the new process as critical to the system. If a critical process terminates for any reason, Windows triggers a bug check (`CRITICAL_PROCESS_DIED` 0xEF). This provides the spawned process with the same protection level as `csrss.exe` or `smss.exe` — killing it via Task Manager or `taskkill` will immediately blue-screen the machine.

---

## Demo

### Debug output (DebugView)

![DebugView log](screenshots/dbgview.png)

Full resolution log:
- `KiSystemCall64` found at `FFFFF805A14BD740` via LSTAR MSR scan
- SSDT located at `FFFFF805A20018C0`, limit 489 entries
- `ntdll.dll` mapped at `00007FFBF7F20000` (size `0x268000`)
- All 5 syscall indices resolved via semi-hardcoded scan (offset 3 — canonical unpatched stubs):

| Function | Index | Kernel address |
|---|---|---|
| `NtCreateUserProcess` | `0xD1` | `FFFFF805A18C7440` |
| `NtResumeThread` | `0x52` | `FFFFF805A180FAE0` |
| `NtQueryInformationProcess` | `0x19` | `FFFFF805A17B3730` |
| `NtWriteVirtualMemory` | `0x3A` | `FFFFF805A17B15B0` |
| `NtReadVirtualMemory` | `0x3F` | `FFFFF805A17B15E0` |

- Environment copied from `csrss.exe` (PID 760, session 1), 1362 bytes
- `NtCreateUserProcess` → `State=6` (`PsCreateSuccess`)
- Entry point resolved: `00007FF7E18A7C70` (RVA `0x27C70`)
- PEB patched: `BeingDebugged = 0`, `NtGlobalFlag = 0`
- Process marked as CRITICAL (`BreakOnTermination = 1`)
- Process running as PID **11120**

---

### Process Hacker — process tree

`cmd.exe` (PID 11120) visible as a direct child of `System (4)`, with a spawned `conhost.exe` (PID 10992):

![Process list](screenshots/prochacker.png)

---

### General tab — parent process anomaly

`Parent: System (4)` — a user-mode Win32 process with System as parent is the clearest indicator of kernel-originated creation. PEB at `0xF4A25B5000`, image type 64-bit:

![General tab](screenshots/general.png)

---

### Environment tab

Environment block captured from `csrss.exe` (session 1) and passed through `RTL_USER_PROCESS_PARAMETERS`. `USERNAME: SYSTEM`, `Path`, `SystemRoot`, `PROCESSOR_ARCHITECTURE: AMD64` all present:

![Environment tab](screenshots/env.png)

---

### Token tab

Running as `NT AUTHORITY\СИСТЕМА` in session 0 with full SYSTEM token — all privileges present, mandatory integrity label at system level:

![Token tab](screenshots/token.png)

---

### Handles tab

Open handles include `\Device\ConDrv` (console driver), registry keys under `HKLM` and `HKU`, directory objects, and the process thread. Standard handle set for a console-mode Win32 process:

![Handles tab](screenshots/handels.png)

---

### Memory tab

Virtual address space layout showing the PEB, thread stack, heap, mapped NLS files, locale data, and all loaded images (`cmd.exe`, `ntdll.dll`, `kernel32.dll`, `KernelBase.dll`, `ucrtbase.dll`, etc.):

![Memory tab](screenshots/memory.png)

---

### Modules tab

Loaded module list — minimal set of DLLs loaded by the Windows PE loader during process initialization. No injected or unusual modules:

![Modules tab](screenshots/modules.png)

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

Attach **DebugView** (kernel capture enabled) or a kernel debugger session to see the full resolution log.

---

## Project structure

```
├── ring0exec/
│   ├── main.c                            # DriverEntry, Unload, global NT API pointers
│   ├── exec.c / exec.h                   # Process creation, parameter building, PEB patching, env capture
│   ├── utils.c / utils.h                 # SSDT scan, ntdll mapping, export lookup, index extraction
│   ├── ntoskrnl.h                        # Undocumented NT structures (RTL_USER_PROCESS_PARAMETERS, PS_CREATE_INFO, SDT ...)
│   ├── _def.h                            # NT API typedefs and extern declarations
│   ├── ring0exec.inf
│   ├── ring0exec.vcxproj
│   └── ring0exec.vcxproj.filters
├── screenshots/
│   ├── dbgview.png
│   ├── prochacker.png
│   ├── general.png
│   ├── env.png
│   ├── token.png
│   ├── handels.png
│   ├── memory.png
│   └── modules.png
├── .gitignore
├── .gitattributes
├── LICENSE.txt
├── ring0exec.sln
└── README.md
```

---

## License

MIT
