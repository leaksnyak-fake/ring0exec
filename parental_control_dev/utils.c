#include "utils.h"

SSDT_CONTEXT g_SsdtCtx = { 0 };

/*
 * DumpUnicodeString  [static]
 *
 * Prints a single UNICODE_STRING field from an RTL_USER_PROCESS_PARAMETERS
 * block via DbgPrint.  Handles both normalized (absolute pointer) and
 * de-normalized (base-relative offset) representations.
 *
 * Parameters:
 *   Name   - label printed in the left column
 *   Str    - pointer to the UNICODE_STRING descriptor inside the params block
 *   Base   - base address of the params block (used for offset resolution)
 *   Flags  - Flags field of the params block; RTL_USER_PROC_PARAMS_NORMALIZED
 *            indicates that Buffer is already an absolute address
 */
static void DumpUnicodeString(const char* Name, PUNICODE_STRING Str, PVOID Base, ULONG Flags) {
    PWSTR RealBuffer = NULL;

    if (Str->Length == 0 || Str->Buffer == NULL) {
        DbgPrint("%-20s: (null)\n", Name);
        return;
    }

    if (Flags & RTL_USER_PROC_PARAMS_NORMALIZED) {
        RealBuffer = Str->Buffer;
    }
    else {
        RealBuffer = (PWSTR)((char*)Base + (ULONG_PTR)Str->Buffer);
    }

    DbgPrint("%-20s: %.*ls\n", Name, Str->Length / sizeof(WCHAR), RealBuffer);
}

/*
 * DumpKernelProcessParameters
 *
 * Prints the contents of an RTL_USER_PROCESS_PARAMETERS structure to the
 * kernel debug output.  Intended for development / diagnostic use.
 * Handles both normalized and de-normalized buffer representations by
 * forwarding Flags to DumpUnicodeString.
 *
 * Parameters:
 *   p - pointer to the process parameters block to dump; may be NULL
 */
void DumpKernelProcessParameters(PRTL_USER_PROCESS_PARAMETERS p) {
    if (!p) {
        DbgPrint("Dump: Parameters pointer is NULL\n");
        return;
    }

    DbgPrint("\n--- KERNEL_RTL_USER_PROCESS_PARAMETERS DUMP ---\n");
    DbgPrint("%-20s: 0x%08X\n", "MaximumLength", p->MaximumLength);
    DbgPrint("%-20s: 0x%08X\n", "Length", p->Length);
    DbgPrint("%-20s: 0x%08X\n", "Flags", p->Flags);
    DbgPrint("%-20s: %p\n", "ConsoleHandle", p->ConsoleHandle);
    DbgPrint("%-20s: 0x%08X\n", "ConsoleFlags", p->ConsoleFlags);

    DbgPrint("\n--- Standard Handles ---\n");
    DbgPrint("%-20s: %p\n", "StandardInput", p->StandardInput);
    DbgPrint("%-20s: %p\n", "StandardOutput", p->StandardOutput);
    DbgPrint("%-20s: %p\n", "StandardError", p->StandardError);

    DbgPrint("\n--- Path & String Parameters ---\n");
    DumpUnicodeString("CurrentDirectory", &p->CurrentDirectory.DosPath, p, p->Flags);
    DumpUnicodeString("ImagePathName", &p->ImagePathName, p, p->Flags);
    DumpUnicodeString("CommandLine", &p->CommandLine, p, p->Flags);
    DumpUnicodeString("DllPath", &p->DllPath, p, p->Flags);
    DumpUnicodeString("WindowTitle", &p->WindowTitle, p, p->Flags);
    DumpUnicodeString("DesktopInfo", &p->DesktopInfo, p, p->Flags);
    DumpUnicodeString("ShellInfo", &p->ShellInfo, p, p->Flags);
    DumpUnicodeString("RuntimeData", &p->RuntimeData, p, p->Flags);

    DbgPrint("\n--- Environment ---\n");
    if (p->Environment) {
        PVOID EnvPtr = (p->Flags & RTL_USER_PROC_PARAMS_NORMALIZED) ?
            p->Environment : OFFSET_TO_PTR(p, p->Environment);
        DbgPrint("%-20s: %p\n", "EnvironmentPtr", EnvPtr);
    }
    DbgPrint("%-20s: %Iu bytes\n", "EnvironmentSize", p->EnvironmentSize);
    DbgPrint("-----------------------------------------------\n\n");
}

/*
 * GetSSDT
 *
 * Locates the kernel Service Descriptor Table (KeServiceDescriptorTable)
 * by scanning the prologue of KiSystemCall64, whose address is read from
 * MSR 0xC0000082 (LSTAR).  The scan looks for the LEA R10, [KiServiceTable]
 * encoding (4C 8D 15 <rel32>) within the first 4096 bytes of the handler
 * and resolves the RIP-relative displacement to an absolute address.
 *
 * Must be called at IRQL <= DISPATCH_LEVEL with the target CPU's LSTAR
 * MSR accessible (i.e. from kernel mode on the current logical processor).
 *
 * Returns:
 *   Pointer to the ServiceTable array on success, NULL if the pattern
 *   was not found within the scan range.
 */
PULONGLONG GetSSDT()
{
    ULONGLONG KiSystemCall64 = __readmsr(0xC0000082);
    ULONGLONG KiSystemServiceRepeat = 0;
    INT32     Limit = 4096;

    for (int i = 0; i < Limit; i++)
    {
        if (*(PUINT8)(KiSystemCall64 + i) == 0x4C
            && *(PUINT8)(KiSystemCall64 + i + 1) == 0x8D
            && *(PUINT8)(KiSystemCall64 + i + 2) == 0x15)
        {
            KiSystemServiceRepeat = KiSystemCall64 + i;
            DbgPrint("KiSystemCall64          %p\n", (PVOID)KiSystemCall64);
            DbgPrint("KiSystemServiceRepeat   %p\n", (PVOID)KiSystemServiceRepeat);
            return (PULONGLONG)(*(PINT32)(KiSystemServiceRepeat + 3)
                + KiSystemServiceRepeat + 7);
        }
    }
    return NULL;
}

/*
 * MapNtdll
 *
 * Maps ntdll.dll into the current process (kernel process context) as a
 * read-only image section so that its export directory can be inspected
 * without copying the file to pool memory.  The caller is responsible for
 * unmapping and closing the section via SsdtContextFree or directly with
 * ZwUnmapViewOfSection / ZwClose.
 *
 * Parameters:
 *   OutBase    - receives the virtual address of the mapped view
 *   OutSize    - receives the size of the mapped view in bytes
 *   OutSection - receives the section handle (kernel handle)
 *
 * Returns:
 *   STATUS_SUCCESS on success, or the failing NTSTATUS from ZwOpenFile,
 *   ZwCreateSection, or ZwMapViewOfSection.  On failure the section handle
 *   is closed before returning.
 */
NTSTATUS MapNtdll(PVOID* OutBase, PSIZE_T OutSize, PHANDLE OutSection)
{
    UNICODE_STRING    filePath;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK   ioStatus;
    HANDLE            fileHandle;
    NTSTATUS          status;

    RtlInitUnicodeString(&filePath, L"\\SystemRoot\\System32\\ntdll.dll");
    InitializeObjectAttributes(&objAttr, &filePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenFile(&fileHandle,
        GENERIC_READ | SYNCHRONIZE,
        &objAttr, &ioStatus,
        FILE_SHARE_READ,
        FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) {
        DbgPrint("MapNtdll: ZwOpenFile failed: 0x%X\n", status);
        return status;
    }

    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = ZwCreateSection(OutSection,
        SECTION_MAP_READ,
        &objAttr, NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        fileHandle);
    ZwClose(fileHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("MapNtdll: ZwCreateSection failed: 0x%X\n", status);
        return status;
    }

    *OutBase = NULL;
    *OutSize = 0;
    status = ZwMapViewOfSection(*OutSection,
        ZwCurrentProcess(),
        OutBase,
        0, 0, NULL,
        OutSize,
        ViewUnmap,
        0,
        PAGE_READONLY);
    if (!NT_SUCCESS(status)) {
        DbgPrint("MapNtdll: ZwMapViewOfSection failed: 0x%X\n", status);
        ZwClose(*OutSection);
    }
    return status;
}

/*
 * GetExportByName
 *
 * Resolves a named export from a PE image already mapped into memory.
 * Walks the export directory using the name table / ordinal table pair and
 * returns the raw RVA-resolved address of the function stub.
 *
 * Does not follow forwarder strings.
 *
 * Parameters:
 *   base     - base address of the mapped PE image
 *   funcName - null-terminated ASCII name of the export to locate
 *
 * Returns:
 *   Absolute address of the export stub, or NULL if the image is malformed
 *   or the name was not found.
 */
PVOID GetExportByName(PVOID base, const char* funcName)
{
    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)base;
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS64 ntHdr =
        (PIMAGE_NT_HEADERS64)((PUINT8)base + dosHdr->e_lfanew);
    if (ntHdr->Signature != IMAGE_NT_SIGNATURE) return NULL;

    ULONG exportRva = ntHdr->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRva) return NULL;

    PIMAGE_EXPORT_DIRECTORY expDir =
        (PIMAGE_EXPORT_DIRECTORY)((PUINT8)base + exportRva);

    PUINT32 nameTable = (PUINT32)((PUINT8)base + expDir->AddressOfNames);
    PUINT16 ordTable = (PUINT16)((PUINT8)base + expDir->AddressOfNameOrdinals);
    PUINT32 funcTable = (PUINT32)((PUINT8)base + expDir->AddressOfFunctions);

    for (UINT32 i = 0; i < expDir->NumberOfNames; i++)
    {
        const char* name = (const char*)((PUINT8)base + nameTable[i]);
        if (strcmp(name, funcName) == 0) {
            UINT16 ord = ordTable[i];
            return (PVOID)((PUINT8)base + funcTable[ord]);
        }
    }
    return NULL;
}

/*
 * ExtractSyscallIndexSemiHardcoded  [static helper]
 *
 * Extracts a syscall index from an ntdll stub by scanning forward for a
 * MOV EAX, imm32 (0xB8) instruction whose immediate value is below 0x2000.
 * Stops early if a SYSCALL (0F 05), RET (C3), or RET imm16 (C2) opcode is
 * encountered before finding the index.
 *
 * Handles stubs that have been patched by user-mode hooks (e.g. antivirus
 * trampolines) where the canonical first-instruction pattern is displaced.
 *
 * Parameters:
 *   p      - pointer to the start of the stub bytes
 *   pIndex - receives the syscall index on success
 *
 * Returns:
 *   TRUE if a valid index was found, FALSE otherwise.
 */
BOOLEAN ExtractSyscallIndexSemiHardcoded(PUCHAR p, PULONG pIndex)
{
    ULONG i;
    for (i = 0; i < 32 - sizeof(ULONG); i++)
    {
        if (p[i] == 0xB8)   /* MOV EAX, imm32 */
        {
            ULONG index = *(PULONG)(p + i + 1);
            if (index < 0x2000)
            {
                DbgPrint("ExtractSyscallIndex [semi-hardcoded]: "
                    "found at offset %lu, index = 0x%X\n", i, index);
                *pIndex = index;
                return TRUE;
            }
        }

        if ((p[i] == 0x0F && p[i + 1] == 0x05)   /* syscall */
            || p[i] == 0xC3                        /* ret     */
            || p[i] == 0xC2)                       /* ret imm */
        {
            DbgPrint("ExtractSyscallIndex [semi-hardcoded]: "
                "hit syscall/ret at offset %lu\n", i);
            break;
        }
    }
    return FALSE;
}

/*
 * ExtractSyscallIndexHardcoded  [static helper]
 *
 * Extracts a syscall index assuming the canonical unpatched ntdll stub
 * layout: MOV R10, RCX (4C 8B D1) followed immediately by MOV EAX, imm32
 * (B8 XX XX 00 00).  The four bytes at p[4..7] are interpreted directly as
 * the little-endian ULONG syscall index.
 *
 * Parameters:
 *   p      - pointer to the first byte of the stub
 *   pIndex - receives the syscall index on success
 *
 * Returns:
 *   TRUE if the expected byte pattern was matched, FALSE otherwise.
 */
BOOLEAN ExtractSyscallIndexHardcoded(PUCHAR p, PULONG pIndex)
{
    /* Pattern: 4C 8B D1 (mov r10,rcx) + B8 XX XX 00 00 (mov eax, index) */
    if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8)
    {
        ULONG index = *(PULONG)(p + 4);
        DbgPrint("ExtractSyscallIndex [hardcoded]: index = 0x%X\n", index);
        *pIndex = index;
        return TRUE;
    }

    DbgPrint("ExtractSyscallIndex [hardcoded]: pattern mismatch, "
        "bytes: %02X %02X %02X %02X\n",
        p[0], p[1], p[2], p[3]);
    return FALSE;
}

/*
 * ExtractSyscallIndex
 *
 * Determines the syscall number for an ntdll function stub using a two-stage
 * fallback strategy:
 *   1. Semi-hardcoded scan (ExtractSyscallIndexSemiHardcoded) — tolerates
 *      user-mode hook trampolines by scanning forward for MOV EAX, imm32.
 *   2. Hardcoded pattern match (ExtractSyscallIndexHardcoded) — matches the
 *      exact canonical x64 stub prologue if stage 1 fails.
 *
 * Parameters:
 *   pFunc  - address of the ntdll function stub (from GetExportByName)
 *   pIndex - receives the resolved syscall index on success
 *
 * Returns:
 *   TRUE if either method succeeded, FALSE if both failed.
 */
BOOLEAN
ExtractSyscallIndex(
    PVOID      pFunc,
    OUT PULONG pIndex
)
{
    PUCHAR p = (PUCHAR)pFunc;

    if (ExtractSyscallIndexSemiHardcoded(p, pIndex))
        return TRUE;

    DbgPrint("ExtractSyscallIndex: semi-hardcoded failed, "
        "falling back to hardcoded\n");

    if (ExtractSyscallIndexHardcoded(p, pIndex))
        return TRUE;

    DbgPrint("ExtractSyscallIndex: both methods failed\n");
    return FALSE;
}

/*
 * DecodeSSDTEntry
 *
 * Decodes a single encoded entry from the SSDT ServiceTable and returns the
 * absolute kernel address of the corresponding system-call handler.
 *
 * The encoding used since Windows Vista x64: each 32-bit entry stores a
 * signed offset from the ServiceTable base in bits [31:4]; bits [3:0] hold
 * the argument stack size and are discarded here (right-shift by 4).
 *
 * Parameters:
 *   ssdt  - pointer to the SDT structure (KeServiceDescriptorTable entry)
 *   index - zero-based syscall index; must be < ssdt->Limit
 *
 * Returns:
 *   Absolute address of the kernel handler, or 0 if index is out of range.
 */
ULONGLONG DecodeSSDTEntry(SDT* ssdt, ULONG index)
{
    if (index >= ssdt->Limit) return 0;
    UINT32 entry = ssdt->ServiceTable[index];
    return (ULONGLONG)ssdt->ServiceTable + (entry >> 4);
}

/*
 * SsdtContextInit
 *
 * Initializes an SSDT_CONTEXT by locating the SSDT via GetSSDT() and mapping
 * ntdll.dll into the current address space via MapNtdll().  Both steps must
 * succeed; on any failure the context is left in a partially initialized
 * state and the caller should not use it further (no cleanup is performed
 * here — call SsdtContextFree only if the function returns STATUS_SUCCESS).
 *
 * Parameters:
 *   ctx - caller-allocated SSDT_CONTEXT to initialize
 *
 * Returns:
 *   STATUS_SUCCESS on success.
 *   STATUS_NOT_FOUND if the SSDT pattern was not located.
 *   Propagated NTSTATUS from MapNtdll on mapping failure.
 */
NTSTATUS SsdtContextInit(PSSDT_CONTEXT ctx)
{
    ctx->Ssdt = (SDT*)GetSSDT();
    if (!ctx->Ssdt) {
        DbgPrint("SsdtContextInit: failed to locate SSDT\n");
        return STATUS_NOT_FOUND;
    }
    DbgPrint("SSDT @ %p, Limit = %u\n", ctx->Ssdt, ctx->Ssdt->Limit);

    NTSTATUS status = MapNtdll(&ctx->NtdllBase, &ctx->NtdllSize, &ctx->hSection);
    if (!NT_SUCCESS(status)) {
        DbgPrint("SsdtContextInit: MapNtdll failed: 0x%X\n", status);
        return status;
    }
    DbgPrint("ntdll mapped @ %p (size 0x%IX)\n", ctx->NtdllBase, ctx->NtdllSize);

    return STATUS_SUCCESS;
}

/*
 * SsdtContextFree
 *
 * Releases all resources acquired by SsdtContextInit: unmaps the ntdll view
 * and closes the section handle.  Safe to call with a partially initialized
 * context (checks each field before releasing).
 *
 * Parameters:
 *   ctx - SSDT_CONTEXT previously initialized by SsdtContextInit
 */
VOID SsdtContextFree(PSSDT_CONTEXT ctx)
{
    if (ctx->NtdllBase) {
        ZwUnmapViewOfSection(ZwCurrentProcess(), ctx->NtdllBase);
        ctx->NtdllBase = NULL;
    }
    if (ctx->hSection) {
        ZwClose(ctx->hSection);
        ctx->hSection = NULL;
    }
}

/*
 * SsdtGetFuncAddress
 *
 * Resolves the kernel-mode address of an NT system-call handler by:
 *   1. Looking up the function's stub in the mapped ntdll export table.
 *   2. Extracting the syscall index from the stub bytes.
 *   3. Decoding the SSDT entry at that index to obtain the handler address.
 *
 * Parameters:
 *   ctx     - initialized SSDT_CONTEXT (ntdll mapped, SSDT located)
 *   fName   - null-terminated ASCII name of the Nt* export (e.g. "NtCreateUserProcess")
 *   outAddr - receives the resolved handler address on success
 *
 * Returns:
 *   STATUS_SUCCESS on success.
 *   STATUS_NOT_FOUND if the export was not found, the index could not be
 *   extracted, or the index exceeds the SSDT limit.
 */
NTSTATUS SsdtGetFuncAddress(PSSDT_CONTEXT ctx, const char* fName, PULONGLONG outAddr)
{
    PVOID stub = GetExportByName(ctx->NtdllBase, fName);
    if (!stub) {
        DbgPrint("SsdtGetFuncAddress: %s not found in ntdll\n", fName);
        return STATUS_NOT_FOUND;
    }

    ULONG index = 0;
    if (!ExtractSyscallIndex(stub, &index)) {
        DbgPrint("SsdtGetFuncAddress: failed to extract index for %s\n", fName);
        return STATUS_NOT_FOUND;
    }

    ULONGLONG addr = DecodeSSDTEntry(ctx->Ssdt, index);
    if (!addr) {
        DbgPrint("SsdtGetFuncAddress: index 0x%X out of range for %s\n", index, fName);
        return STATUS_NOT_FOUND;
    }

    DbgPrint("%s -> index: 0x%X, addr: %p\n", fName, index, (PVOID)addr);
    *outAddr = addr;
    return STATUS_SUCCESS;
}