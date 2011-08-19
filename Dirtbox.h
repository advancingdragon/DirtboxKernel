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
    typedef struct SHIM_CONTEXT
    {
        DWORD TlsDataSize;
        PKSTART_ROUTINE StartRoutine;
        PVOID StartContext;
        PKSYSTEM_ROUTINE SystemRoutine;
    } *PSHIM_CONTEXT;

    DWORD WINAPI ShimCallback(PVOID Parameter);
    VOID InitializeThreading();
    WORD AllocateLdtEntry(DWORD Base, DWORD Limit);
    VOID FreeLdtEntry(WORD Selector);
    VOID AllocateTib(DWORD TlsDataSize);
    VOID FreeTib();
    static inline VOID SwapTibs()
    {
        __asm
        {
            mov ax, fs:[0x14]
            mov fs, ax
        }
    }

    // DirtboxGraphics.cpp
    DWORD WINAPI GraphicsThreadCallback(PVOID Parameter);
    DWORD InitializeGraphics();

    // DirtboxKernel.cpp
    PVOID WINAPI AvGetSavedDataAddress();
    VOID WINAPI AvSendTVEncoderOption(
        PVOID RegisterBase, DWORD Option, DWORD Param, PDWORD Result
    );
    DWORD WINAPI AvSetDisplayMode(
        PVOID RegisterBase, DWORD Step, DWORD Mode, DWORD Format, 
        DWORD Pitch, DWORD FrameBuffer
    );
    VOID WINAPI AvSetSavedDataAddress(
        PVOID Address
    );
    NTSTATUS WINAPI DbgPrint(
        PSTR Output
    );
    NTSTATUS WINAPI ExQueryNonVolatileSetting(
        DWORD ValueIndex, DWORD *Type, PBYTE Value, SIZE_T ValueLength,
        PSIZE_T ResultLength
    );
    extern DWORD HalDiskCachePartitionCount;
    DWORD WINAPI HalGetInterruptVector(
        DWORD BusInterruptLevel, PKIRQL Irql
    );
    VOID WINAPI HalReadWritePCISpace(
        DWORD BusNumber, DWORD SlotNumber, DWORD RegisterNumber, PVOID Buffer, 
        DWORD Length, BOOLEAN WritePCISpace
    );
    VOID WINAPI HalRegisterShutdownNotification(
        PHAL_SHUTDOWN_REGISTRATION ShutdownRegistration, CHAR Register
    );
    VOID WINAPI HalReturnToFirmware(
        RETURN_FIRMWARE Routine
    );
    NTSTATUS WINAPI IoCreateSymbolicLink(
        PANSI_STRING SymbolicLinkName, PANSI_STRING DeviceName
    );
    NTSTATUS WINAPI IoDeleteSymbolicLink(
        PANSI_STRING SymbolicLinkName
    );
    VOID WINAPI KeBugCheck(
        DWORD BugCheckCode
    );
    BOOLEAN WINAPI KeConnectInterrupt(
        PKINTERRUPT Interrupt
    );
    NTSTATUS WINAPI KeDelayExecutionThread(
        CHAR WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Interval
    );
    BOOLEAN WINAPI KeDisconnectInterrupt(
        PKINTERRUPT Interrupt
    );
    VOID WINAPI KeInitializeDpc(
        PKDPC Dpc, PKDEFERRED_ROUTINE DeferredRoutine, PVOID DeferredContext
    );
    VOID WINAPI KeInitializeInterrupt(
        PKINTERRUPT Interrupt, PKSERVICE_ROUTINE ServiceRoutine, PVOID ServiceContext, DWORD Vector,
        KIRQL Irql, KINTERRUPT_MODE InterruptMode, BOOLEAN ShareVector
    );
    VOID WINAPI KeInitializeTimerEx(
        PKTIMER Timer, TIMER_TYPE Type
    );
    BOOLEAN WINAPI KeInsertQueueDpc(
        PKDPC Dpc, PVOID SystemArgument1, PVOID SystemArgument2
    );
    VOID WINAPI KeQuerySystemTime(
        PLARGE_INTEGER CurrentTime
    );
    KIRQL WINAPI KeRaiseIrqlToDpcLevel();
    BOOLEAN WINAPI KeSetEvent(
        PKEVENT Event, LONG Increment, CHAR Wait
    );
    BOOLEAN WINAPI KeSetTimer(
        PKTIMER Timer, LARGE_INTEGER DueTime, PKDPC Dpc
    );
    NTSTATUS WINAPI KeWaitForSingleObject(
        PVOID Object, KWAIT_REASON WaitReason, CHAR WaitMode, CHAR Alertable, 
        PLARGE_INTEGER Timeout
    );
    DWORD __fastcall KfLowerIrql(KIRQL NewIrql);
    extern DWORD LaunchDataPage;
    PVOID WINAPI MmAllocateContiguousMemory(
        DWORD NumberOfBytes
    );
    PVOID WINAPI MmAllocateContiguousMemoryEx(
        DWORD NumberOfBytes, DWORD LowestAcceptableAddress, DWORD HighestAcceptableAddress,
        DWORD Alignment, DWORD ProtectionType
    );
    PVOID WINAPI MmClaimGpuInstanceMemory(
        DWORD NumberOfBytes, PDWORD NumberOfPaddingBytes
    );
    VOID WINAPI MmFreeContiguousMemory(
        PVOID BaseAddress
    );
    VOID WINAPI MmPersistContiguousMemory(
        PVOID BaseAddress, DWORD NumberOfBytes, BOOLEAN Persist
    );
    DWORD WINAPI MmQueryAddressProtect(
        PVOID VirtualAddress
    );
    DWORD WINAPI MmQueryAllocationSize(
        PVOID BaseAddress
    );
    DWORD WINAPI MmSetAddressProtect(
        PVOID BaseAddress, DWORD NumberOfBytes, DWORD NewProtect
    );
    NTSTATUS WINAPI NtAllocateVirtualMemory(
        PVOID *BaseAddress, DWORD ZeroBits, PDWORD AllocationSize, DWORD AllocationType,
        DWORD Protect
    );
    NTSTATUS WINAPI NtClose(
        HANDLE Handle
    );
    NTSTATUS WINAPI NtCreateFile(
        PHANDLE FileHandle, DWORD DesiredAccess, PXBOX_OBJECT_ATTRIBUTES ObjectAttributes, 
        PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, DWORD FileAttributes, 
        DWORD ShareAccess, DWORD CreateDisposition, DWORD CreateOptions 
    );
    NTSTATUS WINAPI NtDeviceIoControlFile(
        HANDLE FileHandle, PKEVENT Event, PVOID ApcRoutine, PVOID ApcContext, 
        PIO_STATUS_BLOCK IoStatusBlock, DWORD IoControlCode, PVOID InputBuffer, DWORD InputBufferLength, 
        PVOID OutputBuffer, DWORD OutputBufferLength
    );
    NTSTATUS WINAPI NtFlushBuffersFile(
        HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock
    );
    NTSTATUS WINAPI NtFreeVirtualMemory(
        PVOID *BaseAddress, PDWORD FreeSize, DWORD FreeType
    );
    NTSTATUS WINAPI NtFsControlFile(
        HANDLE FileHandle, PKEVENT Event, PVOID ApcRoutine, PVOID ApcContext, 
        PIO_STATUS_BLOCK IoStatusBlock, DWORD IoControlCode, PVOID InputBuffer, DWORD InputBufferLength, 
        PVOID OutputBuffer, DWORD OutputBufferLength
    );
    NTSTATUS WINAPI NtOpenFile(
        PHANDLE FileHandle, ACCESS_MASK DesiredAccess, PXBOX_OBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK IoStatusBlock, DWORD ShareAccess, DWORD OpenOptions
    );
    NTSTATUS WINAPI NtOpenSymbolicLinkObject(
        PHANDLE LinkHandle, PXBOX_OBJECT_ATTRIBUTES ObjectAttributes
    );
    NTSTATUS WINAPI NtQueryInformationFile(
        HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, DWORD Length, 
        FILE_INFORMATION_CLASS FileInformationClass
    );
    NTSTATUS WINAPI NtQuerySymbolicLinkObject(
        HANDLE LinkHandle, PANSI_STRING LinkTarget, PDWORD ReturnedLength
    );
    NTSTATUS WINAPI NtQueryVirtualMemory(
        PVOID BaseAddress, PMEMORY_BASIC_INFORMATION MemoryInformation
    );
    NTSTATUS WINAPI NtQueryVolumeInformationFile(
        HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation, DWORD Length, 
        DWORD FsInformationClass
    );
    NTSTATUS WINAPI NtReadFile(
        HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, DWORD Length, PLARGE_INTEGER ByteOffset
    );
    NTSTATUS WINAPI NtSetInformationFile(
        HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, DWORD Length, 
        DWORD FileInformationClass
    );
    NTSTATUS WINAPI NtWaitForSingleObject(
        HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout
    );
    NTSTATUS WINAPI NtWaitForSingleObjectEx(
        HANDLE Handle, CHAR WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout
    );
    NTSTATUS WINAPI NtWriteFile( 
        HANDLE FileHandle, PVOID Event, PVOID ApcRoutine, PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, DWORD Length, PLARGE_INTEGER ByteOffset
    );
    NTSTATUS WINAPI PsCreateSystemThreadEx(
        PHANDLE ThreadHandle, DWORD ThreadExtensionSize, DWORD KernelStackSize, DWORD TlsDataSize, 
        PDWORD ThreadId, PKSTART_ROUTINE StartRoutine, PVOID StartContext, BOOLEAN CreateSuspended, 
        BOOLEAN DebuggerThread, PKSYSTEM_ROUTINE SystemRoutine
    );
    VOID WINAPI PsTerminateSystemThread(
        NTSTATUS ExitStatus
    );
    NTSTATUS WINAPI RtlCompareMemoryUlong(
        PDWORD Buffer, DWORD Size, DWORD Value
    );
    NTSTATUS WINAPI RtlEnterCriticalSection(
        PXBOX_CRITICAL_SECTION CriticalSection
    );
    NTSTATUS WINAPI RtlEqualString(
        PANSI_STRING String1, PANSI_STRING String2, BOOLEAN CaseInSensitive
    );
    VOID WINAPI RtlInitAnsiString(
        PANSI_STRING DestinationString, PSTR SourceString
    );
    VOID WINAPI RtlInitializeCriticalSection(
        PXBOX_CRITICAL_SECTION CriticalSection
    );
    VOID WINAPI RtlLeaveCriticalSection(
        PXBOX_CRITICAL_SECTION CriticalSection
    );
    LONG WINAPI RtlNtStatusToDosError(
        NTSTATUS Status
    );
    VOID WINAPI RtlRaiseException(
        PEXCEPTION_RECORD ExceptionRecord
    );
    VOID WINAPI RtlUnwind(
        PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue
    );
    extern XBOX_HARDWARE_INFO XboxHardwareInfo;
    extern DWORD XboxHDKey;
    extern DWORD XboxKrnlVersion;
    extern DWORD XeImageFileName;
    NTSTATUS WINAPI XeLoadSection(
        PXBEIMAGE_SECTION Section
    );
    NTSTATUS WINAPI XeUnloadSection(
        PXBEIMAGE_SECTION Section
    );
    VOID WINAPI XcSHAInit(
        PCHAR SHAContext
    );
    VOID WINAPI XcSHAUpdate(
        PCHAR SHAContext, PCHAR Input, DWORD InputLength
    );
    VOID WINAPI XcSHAFinal(
        PCHAR SHAContext, PCHAR Digest
    );
    VOID WINAPI XcHMAC(
        PCHAR KeyMaterial, DWORD DwordKeyMaterial, PCHAR Data, DWORD DwordData, 
        PCHAR Data2, DWORD DwordData2, PCHAR Digest
    );
    extern DWORD IdexChannelObject;
    VOID WINAPI HalInitiateShutdown();

    // Dirtbox.cpp
    VOID EXPORT WINAPI Initialize();
}

#endif
