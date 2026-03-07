/*
 * exec.h
 *
 * Declaration of the kernel-mode process creation entry point.
 * Implementation is in exec.c.
 */

#pragma once
#include "_def.h"

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
NTSTATUS CreateProcessFromKernel(PCWSTR ImagePath, PWSTR CmdLine);