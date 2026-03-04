#include "exec.h"
#include "_def.h"
#include "utils.h"

/* Global NT API function pointers — populated in DriverEntry via SsdtGetFuncAddress. */
pfnNtQueryInformationProcess NtQueryInformationProcess = NULL;
pfnNtWriteVirtualMemory      NtWriteVirtualMemory = NULL;
pfnNtReadVirtualMemory       NtReadVirtualMemory = NULL;
pfnNtCreateUserProcess       NtCreateUserProcess = NULL;
pfnNtResumeThread            NtResumeThread = NULL;

/*
 * Unload
 *
 * Driver unload callback.  Releases the SSDT context (unmaps the ntdll view
 * and closes the section handle) acquired during DriverEntry.
 *
 * Parameters:
 *   DriverObject - driver object passed by the I/O manager; unused
 */
VOID Unload(IN PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    SsdtContextFree(&g_SsdtCtx);
    DbgPrint("[kproc] Driver unloaded\n");
}

/*
 * DriverEntry
 *
 * Driver initialization entry point.  Performs the following steps:
 *   1. Registers the Unload callback.
 *   2. Initializes the global SSDT context (locates SSDT, maps ntdll).
 *   3. Resolves NtCreateUserProcess, NtResumeThread,
 *      NtQueryInformationProcess, NtWriteVirtualMemory, and
 *      NtReadVirtualMemory from the SSDT.
 *   4. Aborts with STATUS_NOT_FOUND if any function pointer is NULL.
 *   5. Invokes CreateProcessFromKernel to launch cmd.exe as a smoke test.
 *
 * Parameters:
 *   DriverObject  - driver object created by the I/O manager
 *   RegistryPath  - driver service registry path; unused
 *
 * Returns:
 *   STATUS_SUCCESS if all initialization steps and process creation succeed.
 *   STATUS_NOT_FOUND if the SSDT context or any required API could not be resolved.
 *   Propagated NTSTATUS from SsdtContextInit or CreateProcessFromKernel on failure.
 */
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = Unload;
    DbgPrint("Driver start");

    NTSTATUS status = SsdtContextInit(&g_SsdtCtx);
    if (!NT_SUCCESS(status))
        return status;

    SsdtGetFuncAddress(&g_SsdtCtx, "NtCreateUserProcess", (PULONGLONG)&NtCreateUserProcess);
    SsdtGetFuncAddress(&g_SsdtCtx, "NtResumeThread", (PULONGLONG)&NtResumeThread);
    SsdtGetFuncAddress(&g_SsdtCtx, "NtQueryInformationProcess", (PULONGLONG)&NtQueryInformationProcess);
    SsdtGetFuncAddress(&g_SsdtCtx, "NtWriteVirtualMemory", (PULONGLONG)&NtWriteVirtualMemory);
    SsdtGetFuncAddress(&g_SsdtCtx, "NtReadVirtualMemory", (PULONGLONG)&NtReadVirtualMemory);

    if (!NtCreateUserProcess)       return STATUS_NOT_FOUND;
    if (!NtResumeThread)            return STATUS_NOT_FOUND;
    if (!NtQueryInformationProcess) return STATUS_NOT_FOUND;
    if (!NtWriteVirtualMemory)      return STATUS_NOT_FOUND;
    if (!NtReadVirtualMemory)       return STATUS_NOT_FOUND;

    status = CreateProcessFromKernel(
        L"\\??\\C:\\Windows\\System32\\cmd.exe",
        L"cmd.exe"
    );

    if (!NT_SUCCESS(status))
        DbgPrint("CreateProcessFromKernel returned: 0x%X", status);

    return STATUS_SUCCESS;
}