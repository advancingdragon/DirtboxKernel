#ifndef _NATIVE_H_
#define _NATIVE_H_

#include "DirtboxTypes.h"

extern "C"
{

NTSTATUS WINAPI NtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress, DWORD ZeroBits, PSIZE_T RegionSize,
    DWORD AllocationType, DWORD Protect
);

NTSTATUS WINAPI NtClose(
    HANDLE Handle
);

NTSTATUS WINAPI NtCreateEvent(
    PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    EVENT_TYPE EventType, BOOLEAN InitialState
);

NTSTATUS WINAPI NtCreateFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, DWORD FileAttributes,
    DWORD ShareAccess, DWORD CreateDisposition, DWORD CreateOptions,
    PVOID EaBuffer, DWORD EaLength
);

NTSTATUS WINAPI NtCreateSemaphore(
    PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    LONG InitialCount, LONG MaximumCount
);

NTSTATUS WINAPI NtDelayExecution(
    BOOLEAN Alertable, PLARGE_INTEGER Interval
);

NTSTATUS WINAPI NtFlushBuffersFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock
);

NTSTATUS WINAPI NtFreeVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, DWORD FreeType
);

NTSTATUS WINAPI NtOpenFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, DWORD ShareAccess, DWORD OpenOptions
);

NTSTATUS WINAPI NtPulseEvent(
    HANDLE EventHandle, PLONG PulseCount
);

NTSTATUS WINAPI NtQueryDirectoryFile(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, DWORD Length, 
    FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, 
    PUNICODE_STRING FileName, BOOLEAN RestartScan
);

NTSTATUS WINAPI NtQueryInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, DWORD Length, 
    FILE_INFORMATION_CLASS FileInformationClass
);

NTSTATUS WINAPI NtQueryVolumeInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation, DWORD Length, 
    FS_INFORMATION_CLASS FsInformationClass
);

NTSTATUS WINAPI NtReadFile(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, DWORD Length, PLARGE_INTEGER ByteOffset,
    PDWORD Key
);

NTSTATUS WINAPI NtReleaseSemaphore(
    HANDLE SemaphoreHandle, LONG ReleaseCount, PLONG PreviousCount
);

NTSTATUS WINAPI NtResumeThread(
    HANDLE ThreadHandle, PDWORD SuspendCount
);

NTSTATUS WINAPI NtSetEvent(
    HANDLE EventHandle, PLONG PreviousState
);

NTSTATUS WINAPI NtSetInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, DWORD Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

NTSTATUS WINAPI NtSetLdtEntries(
    DWORD Selector, LDT_ENTRY Entry, DWORD a, DWORD b, DWORD c
);

NTSTATUS WINAPI NtSuspendThread(
    HANDLE ThreadHandle, PDWORD PreviousSuspendCount
);

DWORD WINAPI NtWaitForSingleObject(
    HANDLE ObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER Timeout
);

NTSTATUS WINAPI NtWriteFile(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, DWORD Length, PLARGE_INTEGER ByteOffset,
    PDWORD Key
);

NTSTATUS WINAPI NtYieldExecution();

NTSTATUS WINAPI RtlAnsiStringToUnicodeString(
    PUNICODE_STRING DestinationString, PANSI_STRING SourceString, 
    BOOLEAN AllocateDestinationString
);

NTSTATUS WINAPI RtlAppendUnicodeToString(
    PUNICODE_STRING Destination, PWSTR Source
);

SIZE_T WINAPI RtlCompareMemoryUlong(
    PVOID Source, SIZE_T Length, DWORD Pattern
);

NTSTATUS WINAPI RtlEnterCriticalSection(
    PRTL_CRITICAL_SECTION CriticalSection
);

LONG WINAPI RtlEqualString(
    PANSI_STRING String1, PANSI_STRING String2, BOOLEAN CaseInSensitive
);

VOID WINAPI RtlInitAnsiString(
    PANSI_STRING DestinationString, PSTR SourceString
);

static inline VOID RtlInitEmptyUnicodeString(
    PUNICODE_STRING DestinationString,
    PWCHAR Buffer,
    WORD BufferSize
)
{
    DestinationString->Length = 0;
    DestinationString->MaximumLength = BufferSize;
    DestinationString->Buffer = Buffer;
}

VOID WINAPI RtlInitializeCriticalSection(
    PRTL_CRITICAL_SECTION CriticalSection
);

VOID WINAPI RtlLeaveCriticalSection(
    PRTL_CRITICAL_SECTION CriticalSection
);

DWORD WINAPI RtlNtStatusToDosError(
    NTSTATUS Status
);

VOID WINAPI RtlRaiseException(
    PEXCEPTION_RECORD ExceptionRecord
);

VOID WINAPI RtlUnwind(
    PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue
);

}

#endif
