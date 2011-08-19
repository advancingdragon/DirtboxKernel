
#ifndef _NATIVE_H_
#define _NATIVE_H_

#include "Dirtbox.h"

static NTSTATUS NAKED WINAPI NtAllocateVirtualMemory(
    HANDLE ProcessHandle, LPVOID *BaseAddress, DWORD_PTR ZeroBits, PSIZE_T RegionSize,
    DWORD AllocationType, DWORD Protect
)
{
    __asm
    {
        mov eax, 0x11
        mov edx, 0x7FFE0300
        call dword ptr [edx]
        ret 0x18
    }
}

static NTSTATUS NAKED WINAPI NtClose(
    HANDLE Handle
)
{
    __asm
    {
        mov eax, 0x19
        mov edx, 0x7FFE0300
        call dword ptr [edx]
        ret 0x04
    }
}

static NTSTATUS NAKED WINAPI NtCreateFile(
    PHANDLE FileHandle, DWORD DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, DWORD FileAttributes,
    DWORD ShareAccess, DWORD CreateDisposition, DWORD CreateOptions,
    LPVOID EaBuffer, DWORD EaLength
)
{
    __asm
    {
        mov eax, 0x25
        mov edx, 0x7FFE0300
        call dword ptr [edx]
        ret 0x2C
    }
}

static NTSTATUS NAKED WINAPI NtDelayExecution(
    BOOLEAN Alertable, PLARGE_INTEGER Interval
)
{
    __asm
    {
        mov eax, 0x3B
        mov edx, 0x7FFE0300
        call dword ptr [edx]
        ret 0x08
    }
}

static NTSTATUS NAKED WINAPI NtFlushBuffersFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock
)
{
    __asm
    {
        mov eax, 0x4D
        mov edx, 0x7FFE0300
        call dword ptr [edx]
        ret 0x08
    }
}

static NTSTATUS NAKED WINAPI NtFreeVirtualMemory(
    HANDLE ProcessHandle, LPVOID *BaseAddress, LPDWORD RegionSize, DWORD FreeType
)
{
    __asm
    {
        mov eax, 0x53
        mov edx, 0x7FFE0300
        call dword ptr [edx]
        ret 0x10
    }
}

static NTSTATUS NAKED WINAPI NtQueryInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
    DWORD Length, FILE_INFORMATION_CLASS FileInformationClass
)
{
    __asm
    {
        mov eax, 0x97
        mov edx, 0x7FFE0300
        call dword ptr [edx]
        ret 0x14
    }
}

static NTSTATUS NAKED WINAPI NtReadFile(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, DWORD Length, PLARGE_INTEGER ByteOffset,
    PDWORD Key)
{
    __asm
    {
        mov eax, 0xB7
        mov edx, 0x7FFE0300
        call dword ptr [edx]
        ret 0x24
    }
}

static NTSTATUS NAKED WINAPI NtSetInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, DWORD Length,
    FILE_INFORMATION_CLASS FileInformationClass
)
{
    __asm
    {
        mov eax, 0xE0
        mov edx, 0x7FFE0300
        call dword ptr [edx]
        ret 0x14
    }
}

static DWORD NAKED WINAPI NtSetLdtEntries(
    DWORD Selector, LDT_ENTRY Entry, DWORD a, DWORD b, DWORD c
)
{
    __asm
    {
        mov eax, 0xE9
        mov edx, 0x7FFE0300
        call dword ptr [edx]
        ret 0x18
    }
}

static DWORD NAKED WINAPI NtWaitForSingleObject(
    HANDLE ObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER Timeout
)
{
    __asm
    {
        mov eax, 0x10F
        mov edx, 0x7FFE0300
        call dword ptr [edx]
        ret 0x0C
    }
}

static NTSTATUS NAKED WINAPI NtWriteFile(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, DWORD Length, PLARGE_INTEGER ByteOffset,
    PDWORD Key)
{
    __asm
    {
        mov eax, 0x112
        mov edx, 0x7FFE0300
        call dword ptr [edx]
        ret 0x24
    }
}

#endif
