
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

static NTSTATUS NAKED WINAPI NtCreateFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
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

#endif
