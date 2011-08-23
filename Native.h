
#ifndef _NATIVE_H_
#define _NATIVE_H_

#include "Dirtbox.h"

#ifdef __cplusplus
extern "C"
{
#endif

NTSTATUS WINAPI NtAllocateVirtualMemory(
    HANDLE ProcessHandle, LPVOID *BaseAddress, DWORD_PTR ZeroBits, PSIZE_T RegionSize,
    DWORD AllocationType, DWORD Protect
);

NTSTATUS WINAPI NtClose(
    HANDLE Handle
);

NTSTATUS WINAPI NtCreateFile(
    PHANDLE FileHandle, DWORD DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, DWORD FileAttributes,
    DWORD ShareAccess, DWORD CreateDisposition, DWORD CreateOptions,
    LPVOID EaBuffer, DWORD EaLength
);

NTSTATUS WINAPI NtDelayExecution(
    BOOLEAN Alertable, PLARGE_INTEGER Interval
);

NTSTATUS WINAPI NtFlushBuffersFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock
);

NTSTATUS WINAPI NtFreeVirtualMemory(
    HANDLE ProcessHandle, LPVOID *BaseAddress, LPDWORD RegionSize, DWORD FreeType
);

NTSTATUS WINAPI NtOpenFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, DWORD ShareAccess, DWORD OpenOptions
);

NTSTATUS WINAPI NtQueryInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, DWORD Length, 
    FILE_INFORMATION_CLASS FileInformationClass
);

NTSTATUS WINAPI NtQueryVolumeInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation, ULONG Length, 
    FILE_INFORMATION_CLASS FsInformationClass
);

NTSTATUS WINAPI NtReadFile(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, DWORD Length, PLARGE_INTEGER ByteOffset,
    PDWORD Key
);

NTSTATUS WINAPI NtSetInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, DWORD Length,
    FILE_INFORMATION_CLASS FileInformationClass
);

NTSTATUS WINAPI NtSetLdtEntries(
    DWORD Selector, LDT_ENTRY Entry, DWORD a, DWORD b, DWORD c
);

DWORD WINAPI NtWaitForSingleObject(
    HANDLE ObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER Timeout
);

NTSTATUS WINAPI NtWriteFile(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, DWORD Length, PLARGE_INTEGER ByteOffset,
    PDWORD Key
);

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

#ifdef __cplusplus
}
#endif

#endif
