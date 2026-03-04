/*
 * _def.h
 *
 * Function-pointer typedefs for the NT native API functions resolved at
 * runtime through the SSDT, and extern declarations for the corresponding
 * global variables populated in DriverEntry.
 *
 * All signatures follow the official ntdll export ABI (NTAPI / NTSYSCALLAPI
 * calling convention, SAL annotations preserved for static analysis).
 */

#pragma once
#include "ntoskrnl.h"

typedef
NTSYSCALLAPI
NTSTATUS
(NTAPI*
    pfnNtCreateUserProcess)(
        _Out_     PHANDLE                      ProcessHandle,
        _Out_     PHANDLE                      ThreadHandle,
        _In_      ACCESS_MASK                  ProcessDesiredAccess,
        _In_      ACCESS_MASK                  ThreadDesiredAccess,
        _In_opt_  PCOBJECT_ATTRIBUTES          ProcessObjectAttributes,
        _In_opt_  PCOBJECT_ATTRIBUTES          ThreadObjectAttributes,
        _In_      ULONG                        ProcessFlags,
        _In_      ULONG                        ThreadFlags,
        _In_opt_  PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
        _Inout_   PPS_CREATE_INFO              CreateInfo,
        _In_opt_  PPS_ATTRIBUTE_LIST           AttributeList
        );

typedef
NTSYSCALLAPI
NTSTATUS
(NTAPI*
    pfnNtResumeThread)(
        _In_      HANDLE  ThreadHandle,
        _Out_opt_ PULONG  PreviousSuspendCount
        );

typedef
NTSYSCALLAPI
NTSTATUS
(NTAPI*
    pfnNtWriteVirtualMemory)(
        _In_                                        HANDLE  ProcessHandle,
        _In_opt_                                    PVOID   BaseAddress,
        _In_reads_bytes_(NumberOfBytesToWrite)      PVOID   Buffer,
        _In_                                        SIZE_T  NumberOfBytesToWrite,
        _Out_opt_                                   PSIZE_T NumberOfBytesWritten
        );

typedef
NTSYSCALLAPI
NTSTATUS
(NTAPI*
    pfnNtReadVirtualMemory)(
        _In_                                                    HANDLE  ProcessHandle,
        _In_opt_                                                PVOID   BaseAddress,
        _Out_writes_bytes_to_(NumberOfBytesToRead, *NumberOfBytesRead) PVOID Buffer,
        _In_                                                    SIZE_T  NumberOfBytesToRead,
        _Out_opt_                                               PSIZE_T NumberOfBytesRead
        );

typedef
NTSYSCALLAPI
NTSTATUS
(NTAPI*
    pfnNtQueryInformationProcess)(
        _In_                              HANDLE           ProcessHandle,
        _In_                              PROCESSINFOCLASS ProcessInformationClass,
        _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
        _In_                              ULONG            ProcessInformationLength,
        _Out_opt_                         PULONG           ReturnLength
        );

/* Globals populated by SsdtGetFuncAddress() during DriverEntry. */
extern pfnNtQueryInformationProcess NtQueryInformationProcess;
extern pfnNtWriteVirtualMemory      NtWriteVirtualMemory;
extern pfnNtReadVirtualMemory       NtReadVirtualMemory;
extern pfnNtCreateUserProcess       NtCreateUserProcess;
extern pfnNtResumeThread            NtResumeThread;

extern SSDT_CONTEXT g_SsdtCtx;