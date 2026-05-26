#pragma once
// ============================================================
//  SandboxFlt.h  -  Kernel-internal definitions
//  NOT included from user mode code.
// ============================================================
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "SandboxIpc.h"

// ============================================================
//  Pool tag  ('SbFl' reversed = 'lFbS')
// ============================================================
#define SANDBOX_POOL_TAG  'lFbS'

// ============================================================
//  ERESOURCE helper macros
//  ExAcquireResourceXxxLite requires:
//    - IRQL <= APC_LEVEL
//    - APCs disabled (KeEnterCriticalRegion)
//  Always pair ACQUIRE/RELEASE with ENTER/LEAVE.
// ============================================================
#define SbAcquireExclusive(res) \
    KeEnterCriticalRegion(); \
    ExAcquireResourceExclusiveLite((res), TRUE)

#define SbAcquireShared(res) \
    KeEnterCriticalRegion(); \
    ExAcquireResourceSharedLite((res), TRUE)

#define SbRelease(res) \
    ExReleaseResourceLite((res)); \
    KeLeaveCriticalRegion()

// ============================================================
//  Per-box runtime entry (kernel heap)
// ============================================================
typedef struct _BOX_ENTRY {
    LIST_ENTRY      ListEntry;
    UNICODE_STRING  BoxName;
    UNICODE_STRING  SandboxRootNt;
    UNICODE_STRING  RealRootNt;
    SANDBOX_WRITE_POLICY WritePolicy;
    BOOLEAN         RedirectReads;
    BOOLEAN         HideHostFiles;
    WCHAR           BoxNameBuf[SANDBOX_MAX_BOX];
    WCHAR           SandboxRootBuf[SANDBOX_MAX_PATH];
    WCHAR           RealRootBuf[SANDBOX_MAX_PATH];
} BOX_ENTRY, * PBOX_ENTRY;

// ============================================================
//  Per-PID tracking entry (kernel heap)
// ============================================================
typedef struct _PID_ENTRY {
    LIST_ENTRY  ListEntry;
    HANDLE      ProcessId;
    PBOX_ENTRY  Box;
} PID_ENTRY, * PPID_ENTRY;

// ============================================================
//  Global driver context
// ============================================================
typedef struct _SANDBOX_GLOBALS {
    PFLT_FILTER     FilterHandle;
    PDEVICE_OBJECT  ControlDevice;
    PDRIVER_OBJECT  DriverObject;

    LIST_ENTRY      BoxList;
    ERESOURCE       BoxLock;

    LIST_ENTRY      PidList;
    ERESOURCE       PidLock;

    volatile LONG   TotalRedirects;
    volatile LONG   TotalBlocked;
    volatile LONG   TotalPassThrough;

    WCHAR           LastRedirectedPath[SANDBOX_MAX_PATH];
} SANDBOX_GLOBALS, * PSANDBOX_GLOBALS;

extern SANDBOX_GLOBALS g_Sandbox;

// ============================================================
//  C-compatible const pointer helpers
//  PCUNICODE_STRING is already defined in WDK headers as
//  "const UNICODE_STRING *" but SAL annotations on packed
//  struct pointers can confuse the C front-end in some WDK
//  versions.  Use explicit spellings in every prototype.
// ============================================================
#ifndef _CONST_UNICODE_STRING_DEFINED
#define _CONST_UNICODE_STRING_DEFINED
typedef const UNICODE_STRING* PC_UNICODE_STRING;
#endif

// ============================================================
//  Function prototypes
// ============================================================

// Entry / cleanup
DRIVER_INITIALIZE DriverEntry;
NTSTATUS SandboxFlt_Unload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags);

// Filter callbacks
FLT_PREOP_CALLBACK_STATUS
SandboxFlt_PreCreate(
    _Inout_  PFLT_CALLBACK_DATA              Data,
    _In_     PCFLT_RELATED_OBJECTS           FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext);

FLT_POSTOP_CALLBACK_STATUS
SandboxFlt_PostCreate(
    _Inout_  PFLT_CALLBACK_DATA              Data,
    _In_     PCFLT_RELATED_OBJECTS           FltObjects,
    _In_opt_ PVOID                           CompletionContext,
    _In_     FLT_POST_OPERATION_FLAGS        Flags);

// IOCTL dispatch
NTSTATUS SandboxFlt_DispatchCreate(
    _In_ PDEVICE_OBJECT DevObj,
    _In_ PIRP           Irp);

NTSTATUS SandboxFlt_DispatchClose(
    _In_ PDEVICE_OBJECT DevObj,
    _In_ PIRP           Irp);

NTSTATUS SandboxFlt_DispatchIoctl(
    _In_ PDEVICE_OBJECT DevObj,
    _In_ PIRP           Irp);

// Box management
//   Use struct pointer directly (avoids SAL/packed-typedef issue)
NTSTATUS Box_Add(
    _In_ struct _SANDBOX_BOX_INFO* Info);

NTSTATUS Box_Remove(
    _In_ PCWSTR BoxName);

PBOX_ENTRY Box_Find(
    _In_ PC_UNICODE_STRING BoxName);   /* caller holds BoxLock shared */

// PID management
NTSTATUS Pid_Add(
    _In_ ULONG  Pid,
    _In_ PCWSTR BoxName);

NTSTATUS Pid_Remove(
    _In_ ULONG Pid);

PPID_ENTRY Pid_Find(
    _In_ HANDLE Pid);                  /* caller holds PidLock shared */

// Path helpers
BOOLEAN Path_StartsWith(
    _In_ PC_UNICODE_STRING Full,
    _In_ PC_UNICODE_STRING Prefix);

NTSTATUS Path_BuildRedirect(
    _In_  PC_UNICODE_STRING  OriginalPath,
    _In_  PBOX_ENTRY         Box,
    _Out_ PUNICODE_STRING    RedirectedPath,
    _Out_ PWCHAR* AllocatedBuffer);   /* caller: ExFreePool */
