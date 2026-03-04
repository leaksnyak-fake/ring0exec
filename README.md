# parental_control_dev

![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D4)
![Language](https://img.shields.io/badge/language-C%20%28ANSI%29-lightgrey)
![WDK](https://img.shields.io/badge/WDK-10.0-blue)
![Arch](https://img.shields.io/badge/arch-x64%20only-important)

Windows kernel-mode driver that spawns a native process entirely from ring-0 using `NtCreateUserProcess` resolved dynamically through the SSDT — without importing or calling any user-mode launcher.

> ⚠️ Requires kernel debugging or test-signing mode (`bcdedit /set testsigning on`).  
> Load with a kernel debugger attached or via OSR Driver Loader / sc.exe.

---

## How it works

Standard WDK process-creation APIs (`RtlCreateUserProcess`, `PsCreateSystemThread`) either require a kernel-accessible image or don't produce a full Win32 process. This driver takes a different approach:

**1. SSDT resolution**  
The driver reads the `LSTAR` MSR (`0xC0000082`) to get the address of `KiSystemCall64`, then scans its prologue for the `LEA R10, [KiServiceTable]` encoding (`4C 8D 15 <rel32>`) to locate `KeServiceDescriptorTable` at runtime — no hardcoded offsets, no symbol lookups.

**2. Syscall index extraction**  
`ntdll.dll` is mapped into the current address space via `ZwCreateSection` / `ZwMapViewOfSection`. The export directory is walked to find each `Nt*` stub, and the syscall index is extracted from the stub bytes. Two strategies are tried in order:
- *Semi-hardcoded scan* — scans forward for `MOV EAX, imm32` (tolerates user-mode hook trampolines)
- *Hardcoded pattern* — matches the canonical `4C 8B D1 B8 XX XX 00 00` prologue as a fallback

**3. Process parameters**  
`RtlCreateProcessParametersEx` is reimplemented in kernel mode (`MyRtlCreateProcessParametersEx`). It allocates a single paged-pool block containing the `RTL_USER_PROCESS_PARAMETERS` header, all string data, and the environment block — matching the layout the kernel expects. The environment is captured from the first session-1 process found, so the spawned process inherits a usable `PATH` and locale.

**4. Process creation**  
`NtCreateUserProcess` is called with `THREAD_CREATE_FLAGS_CREATE_SUSPENDED`. After creation, the driver reads the PE headers from the new process's virtual memory to locate the entry point, then clears `PEB->BeingDebugged` and `PEB->NtGlobalFlag` before resuming the initial thread.

---

## Requirements

- Windows 10 / 11 x64
- Visual Studio 2019 or 2022
- WDK 10.0 (matched to your SDK version)
- Test-signing enabled **or** kernel debugger attached with DSE bypass

---

## Building

1. Open `parental_control_dev.sln`
2. Select configuration **Release / x64**
3. Build — output: `x64\Release\parental_control_dev.sys`

No external dependencies. All undocumented structures are defined locally in `ntoskrnl.h`.

---

## Loading

```bat
:: Enable test signing (one-time, requires reboot)
bcdedit /set testsigning on

:: Load the driver
sc create kproc type= kernel binPath= C:\path\to\parental_control_dev.sys
sc start kproc

:: Unload
sc stop kproc
sc delete kproc
```

On success, `cmd.exe` will be spawned as a session-1 process. All steps are logged to the kernel debug output — attach **DebugView** (with kernel capture enabled) or a WinDbg session to see them.

<details>
<summary>Example debug output</summary>

```
Driver start
SSDT @ fffff80012345678, Limit = 478
ntdll mapped @ ffff998800000000 (size 0x1F4000)
NtCreateUserProcess -> index: 0xC8, addr: fffff80012AABBCC
...
[kproc] Env copied from PID 1234, size 4096 bytes
[kproc] ProcessParameters built, EnvSize=4096
[kproc] Process created suspended, State=6
[kproc] PEB @ 0x7FF...
[kproc] ImageBase = 00007FF6AABBCC00
[kproc] EntryPoint = 00007FF6AABBDD10 (RVA 0x1110)
[kproc] PEB->BeingDebugged = 0 patched
[kproc] PEB->NtGlobalFlag = 0 patched
[kproc] PID = 5678
[kproc] Driver unloaded
```

</details>


---

## License

MIT
