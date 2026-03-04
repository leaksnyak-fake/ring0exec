/*
 * ntoskrnl.h
 *
 * Kernel-mode type definitions that supplement or replace declarations
 * absent from the WDK headers.  Covers the undocumented portions of
 * RTL_USER_PROCESS_PARAMETERS, PEB, PS_ATTRIBUTE_LIST / PS_CREATE_INFO,
 * the Service Descriptor Table (SDT / SSDT_CONTEXT), and the helper
 * macros used throughout the driver.
 *
 * All structures are laid out to match the x64 Windows kernel ABI.
 * Bit-field unions in PS_CREATE_INFO require warning 4201 suppression.
 */

#pragma once
#include <ntifs.h>
#include <ntimage.h>

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

/*
 * Full layout of RTL_USER_PROCESS_PARAMETERS as seen by the kernel.
 * The public WDK definition exposes only a subset of fields; this one
 * includes EnvironmentSize, EnvironmentVersion, and the loader/thread-
 * pool fields added in later Windows versions.
 *
 * When Flags & RTL_USER_PROC_PARAMS_NORMALIZED is set, all UNICODE_STRING
 * buffers hold absolute virtual addresses.  When the flag is clear, the
 * buffers hold byte offsets from the start of the structure (de-normalized
 * form expected by NtCreateUserProcess).
 */
typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[32];
    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
    UNICODE_STRING RedirectionDllName;
    UNICODE_STRING HeapPartitionName;
    ULONG_PTR DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadContextFlags;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

/*
 * Minimal PEB layout — only the fields accessed by this driver.
 * InheritedAddressSpace through BitField mirror the first four bytes
 * of the real PEB; the remaining fields are at their correct offsets
 * for x64.
 */
typedef struct _PEB {
    UCHAR  InheritedAddressSpace;
    UCHAR  ReadImageFileExecOptions;
    UCHAR  BeingDebugged;
    UCHAR  BitField;
    PVOID  Mutant;
    PVOID  ImageBaseAddress;
    PVOID  Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
} PEB, * PPEB;

/* Kernel-side buffer descriptor for a captured environment block. */
typedef struct _ENV_BLOCK {
    PVOID   Buffer;
    SIZE_T  Size;
} ENV_BLOCK, * PENV_BLOCK;

#pragma warning(push)
#pragma warning(disable: 4201)

/*
 * PS_ATTRIBUTE / PS_ATTRIBUTE_LIST
 *
 * Attribute vector passed to NtCreateUserProcess.  TotalLength must equal
 * FIELD_OFFSET(PS_ATTRIBUTE_LIST, Attributes) + n * sizeof(PS_ATTRIBUTE)
 * for exactly n entries; any mismatch yields STATUS_INVALID_PARAMETER.
 */
typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[2];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

/* States reported by NtCreateUserProcess via PS_CREATE_INFO.State. */
typedef enum _PS_CREATE_STATE
{
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName,
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;

/*
 * PS_CREATE_INFO
 *
 * In/out structure for NtCreateUserProcess.  The caller sets Size and
 * State = PsCreateInitialState before the call; on success the kernel
 * fills SuccessState with PEB address, section handle, and output flags.
 */
typedef struct _PS_CREATE_INFO
{
    SIZE_T Size;
    PS_CREATE_STATE State;
    union
    {
        struct
        {
            union
            {
                ULONG InitFlags;
                struct
                {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                } s1;
            } u1;
            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        struct { HANDLE FileHandle; } FailSection;
        struct { USHORT DllCharacteristics; } ExeFormat;
        struct { HANDLE IFEOKey; } ExeName;

        struct
        {
            union
            {
                ULONG OutputFlags;
                struct
                {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1;
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                } s2;
            } u2;
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, * PPS_CREATE_INFO;
#pragma warning(pop)

typedef enum _PS_ATTRIBUTE_NUM
{
    PsAttributeParentProcess,
    PsAttributeDebugPort,
    PsAttributeToken,
    PsAttributeClientId,
    PsAttributeTebAddress,
    PsAttributeImageName,
    PsAttributeImageInfo,
    PsAttributeMemoryReserve,
    PsAttributePriorityClass,
    PsAttributeErrorMode,
    PsAttributeStdHandleInfo,
    PsAttributeHandleList,
    PsAttributeGroupAffinity,
    PsAttributePreferredNode,
    PsAttributeIdealProcessor,
    PsAttributeUmsThread,
    PsAttributeMitigationOptions,
    PsAttributeProtectionLevel,
    PsAttributeSecureProcess,
    PsAttributeJobList,
    PsAttributeChildProcessPolicy,
    PsAttributeAllApplicationPackagesPolicy,
    PsAttributeWin32kFilter,
    PsAttributeSafeOpenPromptOriginClaim,
    PsAttributeBnoIsolation,
    PsAttributeDesktopAppPolicy,
    PsAttributeMax
} PS_ATTRIBUTE_NUM;

/*
 * SDT — mirrors KeServiceDescriptorTable entry layout.
 * ServiceTable entries are encoded: bits [31:4] = signed offset from
 * ServiceTable base; bits [3:0] = argument byte count (unused here).
 */
typedef struct ServiceDescriptorTable {
    UINT32* ServiceTable;
    UINT32* Count;
    UINT32  Limit;
    UINT32* ArgumentTable;
} SDT;

/* Runtime context that holds a resolved SSDT pointer and a mapped ntdll view. */
typedef struct {
    SDT* Ssdt;
    PVOID   NtdllBase;
    SIZE_T  NtdllSize;
    HANDLE  hSection;
} SSDT_CONTEXT, * PSSDT_CONTEXT;

/* -----------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------- */

#define RTL_USER_PROC_PARAMS_NORMALIZED    0x00000001
#define PROCESS_QUERY_INFORMATION          (0x0400)
#define PROCESS_VM_READ                    (0x0010)
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001

#define ENV_POOL_TAG            'vnEK'
#define PEB_POOL_TAG            'bePK'
#define RTL_PROCESS_PARAMS_TAG  'rpPK'

#define PS_ATTRIBUTE_NUMBER_MASK  0x0000ffff
#define PS_ATTRIBUTE_THREAD       0x00010000
#define PS_ATTRIBUTE_INPUT        0x00020000
#define PS_ATTRIBUTE_ADDITIVE     0x00040000

#define PEB_BEING_DEBUGGED_OFFSET  0x002
#define PEB_NT_GLOBAL_FLAG_OFFSET  0x0BC
#define PEB_IMAGE_BASE_OFFSET      0x010

 /* -----------------------------------------------------------------------
  * Macros
  * --------------------------------------------------------------------- */

  /*
   * OFFSET_TO_PTR / PTR_TO_OFFSET
   * Convert between a base-relative byte offset stored in a pointer field
   * and the corresponding absolute virtual address, and vice versa.
   * A NULL/zero value passes through unchanged.
   */
#define OFFSET_TO_PTR(base, offset) \
    ((offset) ? (PVOID)((char*)(base) + (ULONG_PTR)(offset)) : NULL)

#define PTR_TO_OFFSET(base, ptr) \
    ((ptr) ? (ULONG_PTR)((char*)(ptr) - (char*)(base)) : 0)

   /* Round size up to the next ULONG_PTR boundary. */
#define ALIGN_SIZE(size) \
    (((size) + sizeof(ULONG_PTR) - 1) & ~(sizeof(ULONG_PTR) - 1))

/*
 * PsAttributeValue — compose the Attribute field for PS_ATTRIBUTE.
 *   Number   : PS_ATTRIBUTE_NUM value
 *   Thread   : TRUE if the attribute targets the initial thread
 *   Input    : TRUE if the attribute is an input to the kernel
 *   Additive : TRUE if the attribute is merged with inherited state
 */
#define PsAttributeValue(Number, Thread, Input, Additive) \
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
    ((Thread)   ? PS_ATTRIBUTE_THREAD   : 0) | \
    ((Input)    ? PS_ATTRIBUTE_INPUT    : 0) | \
    ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

 /* Attribute tag for supplying the NT image path to NtCreateUserProcess. */
#define PS_ATTRIBUTE_IMAGE_NAME \
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)

/* -----------------------------------------------------------------------
 * Kernel API declarations missing from ntifs.h
 * --------------------------------------------------------------------- */
NTKERNELAPI PPEB  NTAPI PsGetProcessPeb(PEPROCESS Process);
NTKERNELAPI ULONG NTAPI PsGetProcessSessionId(PEPROCESS Process);