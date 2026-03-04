/*
 * utils.h
 *
 * Declarations for SSDT resolution utilities:
 *   - SSDT base address scan via KiSystemCall64 (MSR 0xC0000082)
 *   - ntdll.dll kernel mapping / unmapping
 *   - PE export lookup
 *   - syscall index extraction (two strategies: pattern scan + fixed stub)
 *   - SSDT entry decoding
 *   - SSDT_CONTEXT lifecycle management
 *
 * All functions are implemented in utils.c.
 * The global SSDT_CONTEXT instance (g_SsdtCtx) is defined in utils.c and
 * extern-declared in _def.h.
 */

#pragma once
#include "_def.h"

PULONGLONG GetSSDT();

NTSTATUS MapNtdll(
    PVOID* OutBase,
    PSIZE_T  OutSize,
    PHANDLE  OutSection);

PVOID GetExportByName(
    PVOID       base,
    const char* funcName);

BOOLEAN ExtractSyscallIndexSemiHardcoded(
    PUCHAR  p,
    PULONG  pIndex);

BOOLEAN ExtractSyscallIndexHardcoded(
    PUCHAR  p,
    PULONG  pIndex);

BOOLEAN ExtractSyscallIndex(
    PVOID       pFunc,
    OUT PULONG  pIndex);

ULONGLONG DecodeSSDTEntry(
    SDT* ssdt,
    ULONG index);

NTSTATUS SsdtContextInit(PSSDT_CONTEXT ctx);
VOID     SsdtContextFree(PSSDT_CONTEXT ctx);

NTSTATUS SsdtGetFuncAddress(
    PSSDT_CONTEXT ctx,
    const char* fName,
    PULONGLONG    outAddr);