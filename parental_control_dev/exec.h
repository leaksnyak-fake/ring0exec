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
  * Creates and resumes a native Win32 process entirely from kernel mode using
  * NtCreateUserProcess resolved through the SSDT.
  *
  * Parameters:
  *   ImagePath - NT namespace path to the executable image
  *               (e.g. L"\\??\\C:\\Windows\\System32\\cmd.exe")
  *   CmdLine   - command-line string passed in ProcessParameters
  *
  * Returns:
  *   STATUS_SUCCESS if the process was created and resumed successfully.
  *   Propagated NTSTATUS from any failing step (parameter build, environment
  *   capture, NtCreateUserProcess, etc.).
  */
NTSTATUS CreateProcessFromKernel(PCWSTR ImagePath, PWSTR CmdLine);