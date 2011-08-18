#ifndef _DIRTBOX_H_
#define _DIRTBOX_H_

#include "DirtboxTypes.h"
#include <stdio.h>

#define EXPORT __declspec(dllexport)
#define NAKED __declspec(naked)

#define ENTRY_POINT_ADDR            0x00010128
#define KERNEL_IMAGE_THUNK_ADDR     0x00010158
#define DEBUG_KEY                   0xEFB1F152

#define TRIGGER_ADDRESS     0x80000000
#define REGISTER_BASE       0x84000000

#define NV_PFIFO_RAMHT          0x002210
#define NV_PFIFO_RAMFC          0x002214
#define NV_PFIFO_RUNOUT_STATUS  0x002400
#define NV_PFIFO_CACHE1_STATUS  0x003214
#define NV_PFB_WC_CACHE         0x100410
#define NV_GPU_INST             0x700000
#define NV_USER                 0x800000
#define USER_DMA_PUT            0x800040
#define USER_DMA_GET            0x800044
#define USER_NV_USER_ADDRESS    0x801C20

#define PADDING_SIZE  0x10000
#define GPU_INST_SIZE 0x5000

#define REG32(offset) (*(DWORD *)(REGISTER_BASE + (offset)))
#define GPU_INST_ADDRESS(offset) (REGISTER_BASE + NV_GPU_INST + PADDING_SIZE + (offset))

#define STATUS_SUCCESS               ((NTSTATUS)0x00000000L)
#define STATUS_OBJECT_NAME_COLLISION ((NTSTATUS)0xC0000035L)
#define STATUS_NOT_A_DIRECTORY       ((NTSTATUS)0xC0000103L)

#define OB_DOS_DEVICES ((HANDLE) 0xFFFFFFFD)

#define DEBUG_PRINT(str, ...) \
    do \
    { \
        printf(str, __VA_ARGS__); \
        fflush(stdout); \
    } while (0)

namespace Dirtbox
{
    static inline DWORD MyVirtualAlloc(DWORD Address, DWORD Size)
    {
        return (DWORD)VirtualAlloc(
            (PVOID)Address, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
        );
    }

    // DirtboxException.cpp
    LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo);

    // DirtboxThreading.cpp
    static inline void SwapTibs()
    {
        __asm
        {
            mov ax, fs:[0x14]
            mov fs, ax
        }
    }
    VOID InitializeThreading();
    WORD AllocateLdtEntry(DWORD Base, DWORD Limit);
    VOID FreeLdtEntry(WORD Selector);
    VOID AllocateTib();
    VOID FreeTib();

    // DirtboxGraphics.cpp
    DWORD GraphicsThread(PVOID Parameter);
    DWORD InitializeGraphics();

    // DirtboxKernel.cpp
    PVOID NTAPI AvGetSavedDataAddress();
    VOID NTAPI AvSendTVEncoderOption(
        PVOID RegisterBase, DWORD Option, DWORD Param, PDWORD Result
    );
    DWORD NTAPI AvSetDisplayMode(
        PVOID RegisterBase, DWORD Step, DWORD Mode, DWORD Format, 
        DWORD Pitch, DWORD FrameBuffer
    );
    VOID NTAPI AvSetSavedDataAddress(
        PVOID Address
    );
    NTSTATUS NTAPI DbgPrint(
        PSTR Output
    );
    NTSTATUS NTAPI ExQueryNonVolatileSetting(
        DWORD ValueIndex, DWORD *Type, PBYTE Value, SIZE_T ValueLength,
        PSIZE_T ResultLength
    );
    extern DWORD HalDiskCachePartitionCount;
    DWORD NTAPI HalGetInterruptVector(
        DWORD BusInterruptLevel, PKIRQL Irql
    );
    VOID NTAPI HalReadWritePCISpace(
        DWORD BusNumber, DWORD SlotNumber, DWORD RegisterNumber, PVOID Buffer, 
        DWORD Length, BOOLEAN WritePCISpace
    );
    VOID NTAPI HalRegisterShutdownNotification(
        PHAL_SHUTDOWN_REGISTRATION ShutdownRegistration, CHAR Register
    );
    VOID NTAPI HalReturnToFirmware(
        RETURN_FIRMWARE Routine
    );
    NTSTATUS NTAPI IoCreateSymbolicLink(
        PANSI_STRING SymbolicLinkName, PANSI_STRING DeviceName
    );
    NTSTATUS NTAPI IoDeleteSymbolicLink(
        PANSI_STRING SymbolicLinkName
    );
    VOID NTAPI KeBugCheck(
        DWORD BugCheckCode
    );
    BOOLEAN NTAPI KeConnectInterrupt(
        PKINTERRUPT Interrupt
    );
    NTSTATUS NTAPI KeDelayExecutionThread(
        CHAR WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Interval
    );
    BOOLEAN NTAPI KeDisconnectInterrupt(
        PKINTERRUPT Interrupt
    );
    VOID NTAPI KeInitializeDpc(
        PKDPC Dpc, PKDEFERRED_ROUTINE DeferredRoutine, PVOID DeferredContext
    );
    VOID NTAPI KeInitializeInterrupt(
        PKINTERRUPT Interrupt, PKSERVICE_ROUTINE ServiceRoutine, PVOID ServiceContext, DWORD Vector,
        KIRQL Irql, KINTERRUPT_MODE InterruptMode, BOOLEAN ShareVector
    );
    VOID NTAPI KeInitializeTimerEx(
        PKTIMER Timer, TIMER_TYPE Type
    );
    BOOLEAN NTAPI KeInsertQueueDpc(
        PKDPC Dpc, PVOID SystemArgument1, PVOID SystemArgument2
    );
    VOID NTAPI KeQuerySystemTime(
        PLARGE_INTEGER CurrentTime
    );
    KIRQL NTAPI KeRaiseIrqlToDpcLevel();
    BOOLEAN NTAPI KeSetEvent(
        PKEVENT Event, LONG Increment, CHAR Wait
    );
    BOOLEAN NTAPI KeSetTimer(
        PKTIMER Timer, LARGE_INTEGER DueTime, PKDPC Dpc
    );
    NTSTATUS NTAPI KeWaitForSingleObject(
        PVOID Object, KWAIT_REASON WaitReason, CHAR WaitMode, CHAR Alertable, 
        PLARGE_INTEGER Timeout
    );
    DWORD __fastcall KfLowerIrql(KIRQL NewIrql);
    extern DWORD LaunchDataPage;
    PVOID NTAPI MmAllocateContiguousMemory(
        DWORD NumberOfBytes
    );
    PVOID NTAPI MmAllocateContiguousMemoryEx(
        DWORD NumberOfBytes, DWORD LowestAcceptableAddress, DWORD HighestAcceptableAddress,
        DWORD Alignment, DWORD ProtectionType
    );
    PVOID NTAPI MmClaimGpuInstanceMemory(
        DWORD NumberOfBytes, PDWORD NumberOfPaddingBytes
    );
    VOID NTAPI MmFreeContiguousMemory(
        PVOID BaseAddress
    );
    VOID NTAPI MmPersistContiguousMemory(
        PVOID BaseAddress, DWORD NumberOfBytes, BOOLEAN Persist
    );
    DWORD NTAPI MmQueryAddressProtect(
        PVOID VirtualAddress
    );
    DWORD NTAPI MmQueryAllocationSize(
        PVOID BaseAddress
    );
    DWORD NTAPI MmSetAddressProtect(
        PVOID BaseAddress, DWORD NumberOfBytes, DWORD NewProtect
    );
    NTSTATUS NTAPI NtAllocateVirtualMemory(
        PVOID *BaseAddress, DWORD ZeroBits, PDWORD AllocationSize, DWORD AllocationType,
        DWORD Protect
    );
    NTSTATUS NTAPI NtClose(
        HANDLE Handle
    );
    NTSTATUS NTAPI NtCreateFile(
        PHANDLE FileHandle, DWORD DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, 
        PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, DWORD FileAttributes, 
        DWORD ShareAccess, DWORD CreateDisposition, DWORD CreateOptions 
    );
    NTSTATUS NTAPI NtDeviceIoControlFile(
        HANDLE FileHandle, PKEVENT Event, PVOID ApcRoutine, PVOID ApcContext, 
        PIO_STATUS_BLOCK IoStatusBlock, DWORD IoControlCode, PVOID InputBuffer, DWORD InputBufferLength, 
        PVOID OutputBuffer, DWORD OutputBufferLength
    );
    NTSTATUS NTAPI NtFlushBuffersFile(
        HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock
    );
    NTSTATUS NTAPI NtFreeVirtualMemory(
        PVOID *BaseAddress, PDWORD FreeSize, DWORD FreeType
    );
    NTSTATUS NTAPI NtFsControlFile(
        HANDLE FileHandle, PKEVENT Event, PVOID ApcRoutine, PVOID ApcContext, 
        PIO_STATUS_BLOCK IoStatusBlock, DWORD IoControlCode, PVOID InputBuffer, DWORD InputBufferLength, 
        PVOID OutputBuffer, DWORD OutputBufferLength
    );
    NTSTATUS NTAPI NtOpenFile(
        PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK IoStatusBlock, DWORD ShareAccess, DWORD OpenOptions
    );
    NTSTATUS NTAPI NtOpenSymbolicLinkObject(
        PHANDLE LinkHandle, POBJECT_ATTRIBUTES ObjectAttributes
    );
    NTSTATUS NTAPI NtQueryInformationFile(
        HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, DWORD Length, 
        FILE_INFORMATION_CLASS FileInformationClass
    );
    NTSTATUS NTAPI NtQuerySymbolicLinkObject(
        HANDLE LinkHandle, PSTR *LinkTarget, PDWORD ReturnedLength
    );
    NTSTATUS NTAPI NtQueryVirtualMemory(
        PVOID BaseAddress, PMEMORY_BASIC_INFORMATION MemoryInformation
    );
    NTSTATUS NTAPI NtQueryVolumeInformationFile(
        HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation, DWORD Length, 
        DWORD FsInformationClass
    );
    NTSTATUS NTAPI NtReadFile(
        HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, DWORD Length, PLARGE_INTEGER ByteOffset
    );
    NTSTATUS NTAPI NtSetInformationFile(
        HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, DWORD Length, 
        DWORD FileInformationClass
    );
    NTSTATUS NTAPI NtWaitForSingleObject(
        HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout
    );
    NTSTATUS NTAPI NtWaitForSingleObjectEx(
        HANDLE Handle, CHAR WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout
    );
    NTSTATUS NTAPI NtWriteFile( 
        HANDLE FileHandle, PVOID Event, PVOID ApcRoutine, PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, DWORD Length, PLARGE_INTEGER ByteOffset
    );
    NTSTATUS NTAPI PsCreateSystemThreadEx(
        PHANDLE ThreadHandle, DWORD ThreadExtraSize, DWORD KernelStackSize, DWORD TlsDataSize, 
        PDWORD ThreadId, PVOID StartContext1, PVOID StartContext2, BOOLEAN CreateSuspended,
        BOOLEAN DebugStack, PKSTART_ROUTINE StartRoutine
    );
    VOID NTAPI PsTerminateSystemThread(
        NTSTATUS ExitStatus
    );
    extern XBOX_HARDWARE_INFO XboxHardwareInfo;

    // Dirtbox.cpp
    VOID EXPORT WINAPI Initialize();
}

#endif
