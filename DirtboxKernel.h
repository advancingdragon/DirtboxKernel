#ifndef _DIRTBOX_KERNEL_H_
#define _DIRTBOX_KERNEL_H_

#include "DirtboxTypes.h"

namespace Dirtbox
{
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

    PVOID WINAPI ExAllocatePool(
        DWORD NumberOfBytes
    );
    PVOID WINAPI ExAllocatePoolWithTag(
        DWORD NumberOfBytes, DWORD Tag
    );
    extern OBJECT_TYPE ExEventObjectType;
    VOID WINAPI ExFreePool(
        PVOID Pool
    );
    DWORD WINAPI ExQueryPoolBlockSize(
        PVOID PoolBlock
    );
    NTSTATUS WINAPI ExQueryNonVolatileSetting(
        DWORD ValueIndex, PDWORD Type, PBYTE Value, SIZE_T ValueLength,
        PSIZE_T ResultLength
    );

    extern DWORD HalDiskCachePartitionCount;
    extern ANSI_STRING HalDiskModelNumber;
    extern ANSI_STRING HalDiskSerialNumber;
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

    PIRP WINAPI IoBuildSynchronousFsdRequest(
        DWORD MajorFunction, PDEVICE_OBJECT DeviceObject, PVOID Buffer, DWORD Length, 
        PLARGE_INTEGER StartingOffset, PKEVENT Event, PIO_STATUS_BLOCK IoStatusBlock
    );
    NTSTATUS WINAPI IoCreateDevice(
        PDRIVER_OBJECT DriverObject, DWORD DeviceExtensionSize, PANSI_STRING DeviceName, 
        DWORD DeviceType, BOOLEAN Exclusive, PDEVICE_OBJECT *DeviceObject
    );
    NTSTATUS WINAPI IoCreateSymbolicLink(
        PANSI_STRING SymbolicLinkName, PANSI_STRING DeviceName
    );
    NTSTATUS WINAPI IoDeleteSymbolicLink(
        PANSI_STRING SymbolicLinkName
    );
    extern OBJECT_TYPE IoFileObjectType;
    NTSTATUS WINAPI IoInvalidDeviceRequest(
        PDEVICE_OBJECT DeviceObject, PIRP Irp
    );
    VOID WINAPI IoStartNextPacket(
        PDEVICE_OBJECT DeviceObject
    );
    VOID WINAPI IoStartPacket(
        PDEVICE_OBJECT DeviceObject, PIRP Irp, PDWORD Key
    );
    NTSTATUS WINAPI IoSynchronousDeviceIoControlRequest(
        DWORD IoControlCode, PDEVICE_OBJECT DeviceObject, 
        PVOID InputBuffer, DWORD InputBufferLength, PVOID OutputBuffer, DWORD OutputBufferLength, 
        PDWORD ReturnedOutputBufferLength, CHAR InternalDeviceIoControl
    );
    NTSTATUS WINAPI IoSynchronousFsdRequest(
        DWORD MajorFunction, PDEVICE_OBJECT DeviceObject, PVOID Buffer, DWORD Length, 
        PLARGE_INTEGER StartingOffset
    );

    NTSTATUS __fastcall IofCallDriver(
        PDEVICE_OBJECT DeviceObject, PIRP Irp
    );
    VOID __fastcall IofCompleteRequest(
        PIRP Irp, CHAR PriorityBoost
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
        FS_INFORMATION_CLASS FsInformationClass
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

    SIZE_T WINAPI RtlCompareMemoryUlong(
        PVOID Source, SIZE_T Length, DWORD Pattern
    );
    NTSTATUS WINAPI RtlEnterCriticalSection(
        PXBOX_CRITICAL_SECTION CriticalSection
    );
    LONG WINAPI RtlEqualString(
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
    DWORD WINAPI RtlNtStatusToDosError(
        NTSTATUS Status
    );
    VOID WINAPI RtlRaiseException(
        PEXCEPTION_RECORD ExceptionRecord
    );
    VOID WINAPI RtlUnwind(
        PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue
    );

    extern XBOX_HARDWARE_INFO XboxHardwareInfo;
    extern PCHAR XboxHDKey;
    extern XBOX_KRNL_VERSION XboxKrnlVersion;

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
}

#endif
