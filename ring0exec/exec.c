#include "exec.h"
#include "utils.h"

/*
 * RtlpGetUnicodeStringSize  [static]
 *
 * Returns the aligned pool size required to store the content of a
 * UNICODE_STRING (data bytes + null terminator, rounded up to pointer
 * alignment).  Returns 0 for empty or NULL strings.
 *
 * Parameters:
 *   String - source UNICODE_STRING descriptor
 */
static ULONG RtlpGetUnicodeStringSize(PUNICODE_STRING String) {
    if (String && String->Buffer && String->Length > 0) {
        return ALIGN_SIZE(String->Length + sizeof(WCHAR));
    }
    return 0;
}

/*
 * RtlpCopyUnicodeString  [static]
 *
 * Copies a UNICODE_STRING's data into a contiguous region starting at
 * *Buffer, updates Destination to describe the new location, null-
 * terminates the copy, and advances *Buffer past the consumed bytes
 * (aligned to pointer size).  If Source is empty or NULL, Destination is
 * zeroed out and *Buffer is unchanged.
 *
 * Parameters:
 *   Buffer      - pointer to the write cursor; updated on return
 *   Destination - UNICODE_STRING descriptor to fill in
 *   Source      - source UNICODE_STRING to copy from
 */
static void RtlpCopyUnicodeString(
    unsigned char** Buffer,
    UNICODE_STRING* Destination,
    PUNICODE_STRING Source)
{
    if (Source && Source->Buffer && Source->Length > 0) {
        Destination->Length = Source->Length;
        Destination->MaximumLength = Source->Length + sizeof(WCHAR);
        Destination->Buffer = (PWSTR)(*Buffer);
        RtlCopyMemory(Destination->Buffer, Source->Buffer, Source->Length);
        Destination->Buffer[Source->Length / sizeof(WCHAR)] = 0;
        *Buffer += ALIGN_SIZE(Destination->MaximumLength);
    }
    else {
        Destination->Length = 0;
        Destination->MaximumLength = 0;
        Destination->Buffer = NULL;
    }
}

/*
 * RtlpGetEnvironmentSize  [static]
 *
 * Determines the byte length of a double-null-terminated environment block
 * by scanning forward until the terminating L"\0\0" sequence is found.
 * Includes both terminating null characters in the returned size.
 *
 * Parameters:
 *   Environment - pointer to the start of the environment block; may be NULL
 *
 * Returns:
 *   Size in bytes of the complete environment block, or 0 if Environment is NULL.
 */
static ULONG_PTR RtlpGetEnvironmentSize(PVOID Environment) {
    WCHAR* Scan;
    if (!Environment) return 0;
    Scan = (WCHAR*)Environment;
    while (*Scan != 0 || *(Scan + 1) != 0) { Scan++; }
    return (ULONG_PTR)((char*)(Scan + 2) - (char*)Environment);
}

/*
 * MyRtlDeNormalizeProcessParams
 *
 * Converts all UNICODE_STRING buffers within an RTL_USER_PROCESS_PARAMETERS
 * block from absolute pointers (normalized form) to base-relative byte
 * offsets (de-normalized form).  Clears RTL_USER_PROC_PARAMS_NORMALIZED from
 * Flags.  This is the layout expected by NtCreateUserProcess.
 *
 * No-op if Params is NULL or if the block is already de-normalized.
 *
 * Parameters:
 *   Params - process parameters block to de-normalize in place
 *
 * Returns:
 *   Params (pass-through, same pointer).
 */
PRTL_USER_PROCESS_PARAMETERS NTAPI MyRtlDeNormalizeProcessParams(
    PRTL_USER_PROCESS_PARAMETERS Params)
{
    if (Params && (Params->Flags & RTL_USER_PROC_PARAMS_NORMALIZED)) {
        Params->CurrentDirectory.DosPath.Buffer = (PWSTR)PTR_TO_OFFSET(Params, Params->CurrentDirectory.DosPath.Buffer);
        Params->DllPath.Buffer = (PWSTR)PTR_TO_OFFSET(Params, Params->DllPath.Buffer);
        Params->ImagePathName.Buffer = (PWSTR)PTR_TO_OFFSET(Params, Params->ImagePathName.Buffer);
        Params->CommandLine.Buffer = (PWSTR)PTR_TO_OFFSET(Params, Params->CommandLine.Buffer);
        Params->WindowTitle.Buffer = (PWSTR)PTR_TO_OFFSET(Params, Params->WindowTitle.Buffer);
        Params->DesktopInfo.Buffer = (PWSTR)PTR_TO_OFFSET(Params, Params->DesktopInfo.Buffer);
        Params->ShellInfo.Buffer = (PWSTR)PTR_TO_OFFSET(Params, Params->ShellInfo.Buffer);
        Params->RuntimeData.Buffer = (PWSTR)PTR_TO_OFFSET(Params, Params->RuntimeData.Buffer);
        Params->Flags &= ~RTL_USER_PROC_PARAMS_NORMALIZED;
    }
    return Params;
}

/*
 * MyRtlNormalizeProcessParams
 *
 * Converts all UNICODE_STRING buffers within an RTL_USER_PROCESS_PARAMETERS
 * block from base-relative byte offsets (de-normalized form) to absolute
 * pointers (normalized form).  Sets RTL_USER_PROC_PARAMS_NORMALIZED in
 * Flags.
 *
 * No-op if Params is NULL or if the block is already normalized.
 *
 * Parameters:
 *   Params - process parameters block to normalize in place
 *
 * Returns:
 *   Params (pass-through, same pointer).
 */
PRTL_USER_PROCESS_PARAMETERS NTAPI MyRtlNormalizeProcessParams(
    PRTL_USER_PROCESS_PARAMETERS Params)
{
    if (Params && !(Params->Flags & RTL_USER_PROC_PARAMS_NORMALIZED)) {
        Params->CurrentDirectory.DosPath.Buffer = (PWSTR)OFFSET_TO_PTR(Params, Params->CurrentDirectory.DosPath.Buffer);
        Params->DllPath.Buffer = (PWSTR)OFFSET_TO_PTR(Params, Params->DllPath.Buffer);
        Params->ImagePathName.Buffer = (PWSTR)OFFSET_TO_PTR(Params, Params->ImagePathName.Buffer);
        Params->CommandLine.Buffer = (PWSTR)OFFSET_TO_PTR(Params, Params->CommandLine.Buffer);
        Params->WindowTitle.Buffer = (PWSTR)OFFSET_TO_PTR(Params, Params->WindowTitle.Buffer);
        Params->DesktopInfo.Buffer = (PWSTR)OFFSET_TO_PTR(Params, Params->DesktopInfo.Buffer);
        Params->ShellInfo.Buffer = (PWSTR)OFFSET_TO_PTR(Params, Params->ShellInfo.Buffer);
        Params->RuntimeData.Buffer = (PWSTR)OFFSET_TO_PTR(Params, Params->RuntimeData.Buffer);
        Params->Flags |= RTL_USER_PROC_PARAMS_NORMALIZED;
    }
    return Params;
}

/*
 * GetEnvironmentFromSession1
 *
 * Finds the first process running in session 1, reads its environment block
 * from user-mode memory into a kernel pool allocation, and returns the result
 * via OutEnv.  Intended to obtain a usable environment block for a process
 * being created from session 0 (kernel context), where the driver's own
 * environment is empty or unsuitable.
 *
 * The function iterates over PIDs in steps of 4 starting at 8, skipping PID
 * 4 (System) and any process not in session 1.  It opens each candidate with
 * PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, reads PEB -> ProcessParameters
 * -> Environment, and determines the block size by scanning for the double-
 * null terminator in 4 KB chunks.
 *
 * The caller must free OutEnv->Buffer with ExFreePoolWithTag(..., ENV_POOL_TAG)
 * when it is no longer needed.
 *
 * Parameters:
 *   OutEnv - receives a pointer to the kernel-mode copy of the environment
 *            block and its byte size; zeroed on failure
 *
 * Returns:
 *   STATUS_SUCCESS if an environment block was successfully captured.
 *   STATUS_NOT_FOUND if no suitable session-1 process was found.
 *   STATUS_INSUFFICIENT_RESOURCES on pool allocation failure.
 *   Other propagated NTSTATUS values from NtQueryInformationProcess or
 *   NtReadVirtualMemory on the last attempted process.
 */
NTSTATUS
GetEnvironmentFromSession1(
    _Out_ PENV_BLOCK OutEnv
)
{
    NTSTATUS   status = STATUS_NOT_FOUND;
    PEPROCESS  process = NULL;
    HANDLE     hProcess = NULL;

    OutEnv->Buffer = NULL;
    OutEnv->Size = 0;

    for (ULONG pid = 8; pid < 0x10000; pid += 4)
    {
        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(status)) continue;

        if (PsGetProcessSessionId(process) != 1 || pid <= 4)
        {
            ObDereferenceObject(process);
            continue;
        }

        status = ObOpenObjectByPointer(
            process,
            OBJ_KERNEL_HANDLE,
            NULL,
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            *PsProcessType,
            KernelMode,
            &hProcess
        );

        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(process);
            continue;
        }

        PROCESS_BASIC_INFORMATION pbi = { 0 };
        status = NtQueryInformationProcess(
            hProcess, ProcessBasicInformation,
            &pbi, sizeof(pbi), NULL
        );
        if (!NT_SUCCESS(status)) goto NextProcess;

        PEB peb = { 0 };
        SIZE_T  bytesRead = 0;
        status = NtReadVirtualMemory(
            hProcess, pbi.PebBaseAddress,
            &peb, sizeof(peb), &bytesRead
        );
        if (!NT_SUCCESS(status) || !peb.ProcessParameters) goto NextProcess;

        RTL_USER_PROCESS_PARAMETERS params = { 0 };
        status = NtReadVirtualMemory(
            hProcess, peb.ProcessParameters,
            &params, sizeof(params), &bytesRead
        );
        if (!NT_SUCCESS(status) || !params.Environment) goto NextProcess;

        SIZE_T envSize = 0;
        {
            PVOID  envBase = params.Environment;

            if (!(params.Flags & RTL_USER_PROC_PARAMS_NORMALIZED))
            {
                envBase = (PVOID)((PUCHAR)peb.ProcessParameters
                    + (ULONG_PTR)params.Environment);
            }

            const SIZE_T  CHUNK = 4096;
            PWCHAR tmpBuf = (PWCHAR)ExAllocatePool2(POOL_FLAG_PAGED, CHUNK, ENV_POOL_TAG);
            if (!tmpBuf) goto NextProcess;

            BOOLEAN found = FALSE;
            for (SIZE_T offset = 0; offset < 256 * 1024; offset += CHUNK)
            {
                SIZE_T toRead = CHUNK;
                status = NtReadVirtualMemory(
                    hProcess,
                    (PUCHAR)envBase + offset,
                    tmpBuf, toRead, &bytesRead
                );
                if (!NT_SUCCESS(status) || bytesRead < 2) break;

                ULONG wchars = (ULONG)(bytesRead / sizeof(WCHAR));
                for (ULONG i = 0; i + 1 < wchars; i++)
                {
                    if (tmpBuf[i] == L'\0' && tmpBuf[i + 1] == L'\0')
                    {
                        envSize = offset + (i + 2) * sizeof(WCHAR);
                        found = TRUE;
                        break;
                    }
                }
                if (found) break;
            }
            ExFreePoolWithTag(tmpBuf, ENV_POOL_TAG);

            if (!found || envSize == 0) goto NextProcess;

            PVOID envKernel = ExAllocatePool2(POOL_FLAG_PAGED, envSize, ENV_POOL_TAG);
            if (!envKernel) { status = STATUS_INSUFFICIENT_RESOURCES; goto NextProcess; }

            status = NtReadVirtualMemory(
                hProcess, envBase,
                envKernel, envSize, &bytesRead
            );
            if (!NT_SUCCESS(status))
            {
                ExFreePoolWithTag(envKernel, ENV_POOL_TAG);
                goto NextProcess;
            }

            OutEnv->Buffer = envKernel;
            OutEnv->Size = envSize;

            DbgPrint("[kproc] Env copied from PID %lu, size %zu bytes\n", pid, envSize);
        }

        ZwClose(hProcess);
        ObDereferenceObject(process);
        return STATUS_SUCCESS;

    NextProcess:
        if (hProcess) { ZwClose(hProcess); hProcess = NULL; }
        ObDereferenceObject(process);
    }

    return STATUS_NOT_FOUND;
}

/*
 * GetProcessEntryPoint
 *
 * Reads the PE headers of the main image from a suspended process's virtual
 * memory and computes the absolute address of the image entry point
 * (ImageBase + AddressOfEntryPoint from the optional header).
 *
 * Requires the process handle to have at least PROCESS_VM_READ and
 * PROCESS_QUERY_INFORMATION access.
 *
 * Parameters:
 *   hProcess   - handle to the target process
 *   EntryPoint - receives the absolute entry point address on success;
 *                set to NULL on failure
 *
 * Returns:
 *   STATUS_SUCCESS on success.
 *   STATUS_INVALID_ADDRESS if the PEB was read successfully but ImageBaseAddress is NULL.
 *   STATUS_INVALID_IMAGE_FORMAT if DOS or NT signatures do not match.
 *   Propagated NTSTATUS from NtQueryInformationProcess or NtReadVirtualMemory.
 */
NTSTATUS
GetProcessEntryPoint(
    _In_  HANDLE  hProcess,
    _Out_ PVOID* EntryPoint
)
{
    NTSTATUS             status;
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    PEB              peb = { 0 };
    IMAGE_DOS_HEADER     dosHdr = { 0 };
    IMAGE_NT_HEADERS64   ntHdrs = { 0 };
    SIZE_T               bytesRead = 0;
    PVOID                imageBase;

    *EntryPoint = NULL;

    status = NtQueryInformationProcess(
        hProcess, ProcessBasicInformation,
        &pbi, sizeof(pbi), NULL
    );
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[kproc] GetProcessEntryPoint: NtQueryInformationProcess failed 0x%X\n", status);
        return status;
    }

    status = NtReadVirtualMemory(
        hProcess, pbi.PebBaseAddress,
        &peb, sizeof(peb), &bytesRead
    );
    if (!NT_SUCCESS(status) || !peb.ImageBaseAddress)
    {
        DbgPrint("[kproc] GetProcessEntryPoint: PEB read failed 0x%X\n", status);
        return NT_SUCCESS(status) ? STATUS_INVALID_ADDRESS : status;
    }

    imageBase = peb.ImageBaseAddress;
    DbgPrint("[kproc] ImageBase = %p\n", imageBase);

    status = NtReadVirtualMemory(
        hProcess, imageBase,
        &dosHdr, sizeof(dosHdr), &bytesRead
    );
    if (!NT_SUCCESS(status) || dosHdr.e_magic != IMAGE_DOS_SIGNATURE)
    {
        DbgPrint("[kproc] GetProcessEntryPoint: invalid DOS signature\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    status = NtReadVirtualMemory(
        hProcess,
        (PUCHAR)imageBase + dosHdr.e_lfanew,
        &ntHdrs, sizeof(ntHdrs), &bytesRead
    );
    if (!NT_SUCCESS(status) || ntHdrs.Signature != IMAGE_NT_SIGNATURE)
    {
        DbgPrint("[kproc] GetProcessEntryPoint: invalid NT signature\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    *EntryPoint = (PUCHAR)imageBase
        + ntHdrs.OptionalHeader.AddressOfEntryPoint;

    DbgPrint("[kproc] EntryPoint = %p (RVA 0x%X)\n",
        *EntryPoint,
        ntHdrs.OptionalHeader.AddressOfEntryPoint);

    return STATUS_SUCCESS;
}

/*
 * PatchProcessPeb
 *
 * Clears anti-debug markers in the PEB of a suspended process by writing
 * zero to PEB->BeingDebugged (offset 0x002) and PEB->NtGlobalFlag
 * (offset 0x0BC) via NtWriteVirtualMemory.
 *
 * Non-fatal: failures in individual patches are logged but do not cause
 * this function to return an error code.
 *
 * Parameters:
 *   hProcess - handle to the target process with at least PROCESS_VM_WRITE
 *              and PROCESS_QUERY_INFORMATION access
 *
 * Returns:
 *   STATUS_SUCCESS if the PEB address was resolved successfully (regardless
 *   of individual patch outcomes).
 *   Propagated NTSTATUS from NtQueryInformationProcess on lookup failure.
 */
NTSTATUS
PatchProcessPeb(
    _In_ HANDLE hProcess
)
{
    NTSTATUS                  status;
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    SIZE_T                    written = 0;

    status = NtQueryInformationProcess(
        hProcess, ProcessBasicInformation,
        &pbi, sizeof(pbi), NULL
    );
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[kproc] PatchProcessPeb: NtQueryInformationProcess failed 0x%X\n", status);
        return status;
    }

    PVOID pebBase = pbi.PebBaseAddress;
    DbgPrint("[kproc] PatchProcessPeb: PEB @ %p\n", pebBase);

    {
        UCHAR val = 0;
        status = NtWriteVirtualMemory(
            hProcess,
            (PUCHAR)pebBase + PEB_BEING_DEBUGGED_OFFSET,
            &val, sizeof(val), &written
        );
        if (!NT_SUCCESS(status))
            DbgPrint("[kproc] PatchProcessPeb: BeingDebugged patch failed 0x%X\n", status);
        else
            DbgPrint("[kproc] PEB->BeingDebugged = 0 patched\n");
    }

    {
        ULONG val = 0;
        status = NtWriteVirtualMemory(
            hProcess,
            (PUCHAR)pebBase + PEB_NT_GLOBAL_FLAG_OFFSET,
            &val, sizeof(val), &written
        );
        if (!NT_SUCCESS(status))
            DbgPrint("[kproc] PatchProcessPeb: NtGlobalFlag patch failed 0x%X\n", status);
        else
            DbgPrint("[kproc] PEB->NtGlobalFlag = 0 patched\n");
    }

    return STATUS_SUCCESS;
}

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength
);

/*
 * SetProcessCritical
 *
 * Marks a process as critical to the system by calling NtSetInformationProcess
 * with ProcessBreakOnTermination class. When a critical process terminates,
 * the system will crash with CRITICAL_PROCESS_DIED (0xEF) or
 * KERNEL_SECURITY_CHECK_FAILURE (0x139).
 *
 * Requires the process handle to have PROCESS_SET_INFORMATION access.
 *
 * Parameters:
 *   hProcess - handle to the target process
 *
 * Returns:
 *   STATUS_SUCCESS on success.
 *   Propagated NTSTATUS from NtSetInformationProcess on failure.
 */
NTSTATUS
SetProcessCritical(
    _In_ HANDLE hProcess
)
{
    NTSTATUS status;
    ULONG breakOnTermination = 1;

    status = NtSetInformationProcess(
        hProcess,
        ProcessBreakOnTermination,
        &breakOnTermination,
        sizeof(breakOnTermination)
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[kproc] SetProcessCritical: NtSetInformationProcess failed 0x%X\n", status);
    }
    else
    {
        DbgPrint("[kproc] Process marked as CRITICAL (BreakOnTermination = 1)\n");
    }

    return status;
}

/*
 * MyRtlCreateProcessParametersEx
 *
 * Kernel-mode reimplementation of RtlCreateProcessParametersEx.  Allocates
 * a single paged-pool block that contains the RTL_USER_PROCESS_PARAMETERS
 * header followed by all string data and the environment block, matching the
 * layout produced by the ntdll version as observed in IDA.
 *
 * If Environment is NULL and a current process PEB is accessible, the
 * driver's own environment is used as a fallback.  If the caller does not
 * set RTL_USER_PROC_PARAMS_NORMALIZED in Flags, the block is de-normalized
 * (string buffers converted to offsets) before return.
 *
 * The returned block must be freed with MyRtlDestroyProcessParameters.
 *
 * Parameters:
 *   pProcessParameters - receives the allocated block pointer on success
 *   ImagePathName      - NT path of the image (required)
 *   DllPath            - DLL search path; may be NULL
 *   CurrentDirectory   - initial working directory; may be NULL
 *   CommandLine        - command-line string; may be NULL
 *   Environment        - pointer to a double-null-terminated environment block;
 *                        may be NULL (falls back to current process environment)
 *   WindowTitle        - window title; may be NULL
 *   DesktopInfo        - desktop station\desktop string; may be NULL
 *   ShellInfo          - shell info string; may be NULL
 *   RuntimeData        - runtime data string; may be NULL
 *   Flags              - if RTL_USER_PROC_PARAMS_NORMALIZED is set, buffers are
 *                        left as absolute pointers; otherwise de-normalized
 *
 * Returns:
 *   STATUS_SUCCESS on success.
 *   STATUS_INSUFFICIENT_RESOURCES if the pool allocation fails.
 */
NTSTATUS NTAPI MyRtlCreateProcessParametersEx(
    PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags)
{
    ULONG HeaderSize, TotalSize;
    ULONG_PTR EnvSize = 0;
    PVOID SourceEnv = Environment;
    PRTL_USER_PROCESS_PARAMETERS Params;
    unsigned char* BufferPtr;
    PPEB Peb = PsGetProcessPeb(PsGetCurrentProcess());
    PRTL_USER_PROCESS_PARAMETERS CurrentParams =
        (Peb) ? (PRTL_USER_PROCESS_PARAMETERS)Peb->ProcessParameters : NULL;

    if (!SourceEnv && CurrentParams)
        SourceEnv = CurrentParams->Environment;
    if (SourceEnv)
        EnvSize = RtlpGetEnvironmentSize(SourceEnv);

    HeaderSize = ALIGN_SIZE(sizeof(RTL_USER_PROCESS_PARAMETERS));
    HeaderSize += RtlpGetUnicodeStringSize(ImagePathName);
    HeaderSize += RtlpGetUnicodeStringSize(DllPath);
    HeaderSize += RtlpGetUnicodeStringSize(CurrentDirectory);
    HeaderSize += RtlpGetUnicodeStringSize(CommandLine);
    HeaderSize += RtlpGetUnicodeStringSize(WindowTitle);
    HeaderSize += RtlpGetUnicodeStringSize(DesktopInfo);
    HeaderSize += RtlpGetUnicodeStringSize(ShellInfo);
    HeaderSize += RtlpGetUnicodeStringSize(RuntimeData);

    TotalSize = HeaderSize + (ULONG)ALIGN_SIZE(EnvSize);

    Params = (PRTL_USER_PROCESS_PARAMETERS)ExAllocatePool2(
        POOL_FLAG_PAGED, TotalSize, RTL_PROCESS_PARAMS_TAG);
    if (!Params) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(Params, TotalSize);

    Params->MaximumLength = HeaderSize;
    Params->Length = HeaderSize;
    Params->Flags = RTL_USER_PROC_PARAMS_NORMALIZED;

    BufferPtr = (unsigned char*)Params + ALIGN_SIZE(sizeof(RTL_USER_PROCESS_PARAMETERS));
    RtlpCopyUnicodeString(&BufferPtr, &Params->ImagePathName, ImagePathName);
    RtlpCopyUnicodeString(&BufferPtr, &Params->CommandLine, CommandLine);
    RtlpCopyUnicodeString(&BufferPtr, &Params->DllPath, DllPath);
    RtlpCopyUnicodeString(&BufferPtr, &Params->CurrentDirectory.DosPath, CurrentDirectory);
    RtlpCopyUnicodeString(&BufferPtr, &Params->WindowTitle, WindowTitle);
    RtlpCopyUnicodeString(&BufferPtr, &Params->DesktopInfo, DesktopInfo);
    RtlpCopyUnicodeString(&BufferPtr, &Params->ShellInfo, ShellInfo);
    RtlpCopyUnicodeString(&BufferPtr, &Params->RuntimeData, RuntimeData);

    if (SourceEnv && EnvSize > 0) {
        Params->Environment = (PVOID)BufferPtr;
        RtlCopyMemory(Params->Environment, SourceEnv, EnvSize);
        Params->EnvironmentSize = EnvSize;
    }

    if (CurrentParams) {
        Params->ConsoleHandle = CurrentParams->ConsoleHandle;
        Params->ConsoleFlags = CurrentParams->ConsoleFlags;
        Params->StandardInput = CurrentParams->StandardInput;
        Params->StandardOutput = CurrentParams->StandardOutput;
        Params->StandardError = CurrentParams->StandardError;
    }

    if (!(Flags & RTL_USER_PROC_PARAMS_NORMALIZED))
        MyRtlDeNormalizeProcessParams(Params);

    *pProcessParameters = Params;
    return STATUS_SUCCESS;
}

/*
 * MyRtlDestroyProcessParameters
 *
 * Frees a process parameters block allocated by MyRtlCreateProcessParametersEx.
 *
 * Parameters:
 *   Params - block to free; safe to call with NULL
 */
VOID NTAPI MyRtlDestroyProcessParameters(PRTL_USER_PROCESS_PARAMETERS Params) {
    if (Params) ExFreePoolWithTag(Params, RTL_PROCESS_PARAMS_TAG);
}

/*
 * CreateProcessFromKernel
 *
 * Creates a native Win32 process from kernel mode using NtCreateUserProcess
 * resolved via the SSDT.  The sequence is:
 *   1. Capture a session-1 environment block (best-effort; continues on failure).
 *   2. Build RTL_USER_PROCESS_PARAMETERS via MyRtlCreateProcessParametersEx.
 *   3. Allocate and populate a PS_ATTRIBUTE_LIST with PS_ATTRIBUTE_IMAGE_NAME.
 *   4. Call NtCreateUserProcess with THREAD_CREATE_FLAGS_CREATE_SUSPENDED.
 *   5. Resolve and log the entry point via GetProcessEntryPoint.
 *   6. Clear PEB anti-debug fields via PatchProcessPeb.
 *   7. Mark process as critical via SetProcessCritical.
 *   8. Log the PID, then resume the initial thread via NtResumeThread.
 *
 * All intermediate allocations are released in the Cleanup block regardless
 * of outcome.
 *
 * Parameters:
 *   ImagePath - NT namespace path to the target executable
 *   CmdLine   - command-line string for ProcessParameters
 *
 * Returns:
 *   STATUS_SUCCESS on success, or the first failing NTSTATUS.
 */
NTSTATUS CreateProcessFromKernel(PCWSTR ImagePath, PWSTR CmdLine)
{
    NTSTATUS   Status;
    UNICODE_STRING NtImagePath, CommandLine, DesktopInfo, CurrentDir;
    PRTL_USER_PROCESS_PARAMETERS Params = NULL;
    PS_CREATE_INFO CreateInfo = { 0 };
    PPS_ATTRIBUTE_LIST AttrList = NULL;
    HANDLE hProcess = NULL, hThread = NULL;
    SIZE_T AttrListSize;
    ENV_BLOCK envBlock = { 0 };
    PVOID entryPoint = NULL;

    Status = GetEnvironmentFromSession1(&envBlock);
    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[kproc] Warning: no env from Session1 (0x%X), proceeding empty\n", Status);
        envBlock.Buffer = NULL;
        envBlock.Size = 0;
    }

    RtlInitUnicodeString(&NtImagePath, ImagePath);
    RtlInitUnicodeString(&CommandLine, CmdLine);
    RtlInitUnicodeString(&DesktopInfo, L"WinSta0\\Default");
    RtlInitUnicodeString(&CurrentDir, L"C:\\");

    Status = MyRtlCreateProcessParametersEx(
        &Params,
        &NtImagePath,
        NULL,
        &CurrentDir,
        &CommandLine,
        envBlock.Buffer,
        NULL,
        &DesktopInfo,
        NULL, NULL,
        RTL_USER_PROC_PARAMS_NORMALIZED
    );
    if (!NT_SUCCESS(Status)) goto Cleanup;

    DbgPrint("[kproc] ProcessParameters built, EnvSize=%zu\n", envBlock.Size);

    CreateInfo.Size = sizeof(CreateInfo);
    CreateInfo.State = PsCreateInitialState;

    AttrListSize = FIELD_OFFSET(PS_ATTRIBUTE_LIST, Attributes) + sizeof(PS_ATTRIBUTE);
    AttrList = (PPS_ATTRIBUTE_LIST)ExAllocatePool2(
        POOL_FLAG_PAGED, AttrListSize, 'atRp');
    if (!AttrList) { Status = STATUS_INSUFFICIENT_RESOURCES; goto Cleanup; }

    RtlZeroMemory(AttrList, AttrListSize);
    AttrList->TotalLength = AttrListSize;
    AttrList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    AttrList->Attributes[0].Size = NtImagePath.Length;
    AttrList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;

    Status = NtCreateUserProcess(
        &hProcess,
        &hThread,
        PROCESS_ALL_ACCESS,
        THREAD_ALL_ACCESS,
        NULL, NULL,
        0,
        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
        Params,
        &CreateInfo,
        AttrList
    );

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[kproc] NtCreateUserProcess failed 0x%X, State=%d\n",
            Status, CreateInfo.State);
        goto Cleanup;
    }

    DbgPrint("[kproc] Process created suspended, State=%d\n", CreateInfo.State);
    DbgPrint("[kproc] PEB @ 0x%llX\n", CreateInfo.SuccessState.PebAddressNative);

    Status = GetProcessEntryPoint(hProcess, &entryPoint);
    if (NT_SUCCESS(Status))
        DbgPrint("[kproc] EntryPoint = %p\n", entryPoint);

    Status = PatchProcessPeb(hProcess);
    if (!NT_SUCCESS(Status))
        DbgPrint("[kproc] PatchProcessPeb warning: 0x%X\n", Status);

    Status = SetProcessCritical(hProcess);
    if (!NT_SUCCESS(Status))
        DbgPrint("[kproc] SetProcessCritical warning: 0x%X\n", Status);

    {
        PEPROCESS Process = NULL;
        if (NT_SUCCESS(ObReferenceObjectByHandle(
            hProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            *PsProcessType, KernelMode, (PVOID*)&Process, NULL)))
        {
            DbgPrint("[kproc] PID = %llu\n", (ULONG64)PsGetProcessId(Process));
            ObDereferenceObject(Process);
        }
    }

    NtResumeThread(hThread, NULL);
    Status = STATUS_SUCCESS;

Cleanup:
    if (envBlock.Buffer) ExFreePoolWithTag(envBlock.Buffer, ENV_POOL_TAG);
    if (AttrList)        ExFreePoolWithTag(AttrList, 'atRp');
    if (Params)          MyRtlDestroyProcessParameters(Params);
    if (hThread)         ZwClose(hThread);
    if (hProcess)        ZwClose(hProcess);

    return Status;
}