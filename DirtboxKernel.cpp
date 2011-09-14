// Emulated xboxkrnl.exe functions

#include "DirtboxDefines.h"
#include "DirtboxEmulator.h"
#include "DirtboxKernel.h"
#include "Native.h"

#include <malloc.h>
#include <process.h>


namespace Dirtbox
{
    // TODO: Initialize these structures
    OBJECT_TYPE ExEventObjectType;
    DWORD HalDiskCachePartitionCount;
    ANSI_STRING HalDiskModelNumber;
    ANSI_STRING HalDiskSerialNumber;
    OBJECT_TYPE IoFileObjectType;
    DWORD LaunchDataPage;
    XBOX_HARDWARE_INFO XboxHardwareInfo;
    CHAR XboxHDKey[16];
    XBOX_KRNL_VERSION XboxKrnlVersion;
    DWORD XeImageFileName;
    DWORD IdexChannelObject;

    // TODO: need to put critical sections around each of these
    // in case they are used in a multithreaded way
    PVOID AvpSavedDataAddress = (PVOID)0;

    BOOLEAN IsValidDosPath(PANSI_STRING String);
    NTSTATUS ConvertObjectAttributes(
        POBJECT_ATTRIBUTES Destination, PUNICODE_STRING ObjectName, PWSTR Buffer, 
        PXBOX_OBJECT_ATTRIBUTES Source
    );
}


BOOLEAN Dirtbox::IsValidDosPath(PANSI_STRING String)
{
    return String->Length >= 3 &&
        strpbrk(String->Buffer, "CDTUZcdtuz") == String->Buffer &&
        strncmp(String->Buffer + 1, ":\\", 2) == 0;
}

NTSTATUS Dirtbox::ConvertObjectAttributes(
    POBJECT_ATTRIBUTES Destination, PUNICODE_STRING ObjectName, PWSTR Buffer, 
    PXBOX_OBJECT_ATTRIBUTES Source
)
{
    if (Source->RootDirectory == OB_DOS_DEVICES)
    {
        // validate correctness of path
        if (!IsValidDosPath(Source->ObjectName))
        {
            DebugPrint("ConvertObjectAttributes: Invalid path name.");
            return STATUS_OBJECT_NAME_INVALID;
        }

        // build the new path
        RtlInitEmptyUnicodeString(ObjectName, Buffer, MAX_PATH);
        RtlAnsiStringToUnicodeString(ObjectName, Source->ObjectName, FALSE);

        // ':' is not an allowed char in names, so replace it with _
        ObjectName->Buffer[1] = L'_';

        /*
        // D:\ refers to current directory
        if (ObjectName->Buffer[0] == L'D' || ObjectName->Buffer[0] == L'd')
        {
            // remove D:\ in the beginning of string
            ObjectName->Length -= 3;
            for (SHORT i = 0; i < ObjectName->Length; i++)
                ObjectName->Buffer[i] = ObjectName->Buffer[i + 3];
            ObjectName->Buffer[ObjectName->Length + 1] = L'\0';
        }
        else
        {
            // ':' is not an allowed char in names, so replace it with _
            ObjectName->Buffer[1] = L'_';
        }
        */
    }
    else if (Source->RootDirectory == NULL)
    {
        // build the new path
        RtlInitEmptyUnicodeString(ObjectName, Buffer, MAX_PATH);
        RtlAppendUnicodeToString(ObjectName, L"Dummy");
    }
    else
    {
        DebugPrint("ConvertObjectAttributes: Invalid root directory.");
        return STATUS_UNSUCCESSFUL;
    }

    // Convert XBOX_OBJECT_ATTRIBUTES to Windows NT OBJECT_ATTRIBUTES
    Destination->Length = sizeof(OBJECT_ATTRIBUTES);
    Destination->ObjectName = ObjectName;
    Destination->Attributes = Source->Attributes;
    Destination->RootDirectory = CurrentDirectory;
    Destination->SecurityDescriptor = NULL;
    Destination->SecurityQualityOfService = NULL;

    return STATUS_SUCCESS;
}


PVOID WINAPI Dirtbox::AvGetSavedDataAddress()
{
    SwapTibs();

    DebugPrint("AvGetSavedDataAddress");

    SwapTibs();
    return AvpSavedDataAddress;
}

VOID WINAPI Dirtbox::AvSendTVEncoderOption(
    PVOID RegisterBase, DWORD Option, DWORD Param, PDWORD Result
)
{
    SwapTibs();

    DebugPrint("AvSendTVEncoderOption: 0x%08x %i %i", 
        RegisterBase, Option, Param);

    if (Result != (PDWORD)0)
        *Result = 0;

    SwapTibs();
}

DWORD WINAPI Dirtbox::AvSetDisplayMode(
    PVOID RegisterBase, DWORD Step, DWORD Mode, DWORD Format, 
    DWORD Pitch, DWORD FrameBuffer
)
{
    SwapTibs();
    DebugPrint("AvSetDisplayMode: 0x%08x %i %i %i %i 0x%x", 
        RegisterBase, Step, Mode, Format, Pitch, FrameBuffer);

    SwapTibs();
    return 0;
}

VOID WINAPI Dirtbox::AvSetSavedDataAddress(
    PVOID Address
)
{
    SwapTibs();

    DebugPrint("AvSetSavedDataAddress: 0x%08x", 
        Address);

    AvpSavedDataAddress = Address;

    SwapTibs();
}

NTSTATUS WINAPI Dirtbox::DbgPrint(
    PSTR Output
)
{
    SwapTibs();

    DebugPrint("DbgPrint: \"%s\"", Output);

    SwapTibs();
    return STATUS_SUCCESS;
}

PVOID WINAPI Dirtbox::ExAllocatePool(
    DWORD NumberOfBytes
)
{
    return ExAllocatePoolWithTag(NumberOfBytes, 0x656E6F4E); // "None"
}

PVOID WINAPI Dirtbox::ExAllocatePoolWithTag(
    DWORD NumberOfBytes, DWORD Tag
)
{
    SwapTibs();

    DebugPrint("ExAllocatePoolWithTag: 0x%x 0x%x", NumberOfBytes, Tag);

    // Don't see how Tag could be used
    PVOID Res = malloc(NumberOfBytes);

    SwapTibs();
    return Res;
}

VOID WINAPI Dirtbox::ExFreePool(
    PVOID Pool
)
{
    SwapTibs();

    DebugPrint("ExFreePool: 0x%08x", Pool);

    free(Pool);

    SwapTibs();
}

DWORD WINAPI Dirtbox::ExQueryPoolBlockSize(
    PVOID PoolBlock
)
{
    SwapTibs();

    DebugPrint("ExQueryPoolBlockSize: 0x%08x", PoolBlock);

    DWORD Res = (DWORD)_msize(PoolBlock);

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::ExQueryNonVolatileSetting(
    XC_VALUE_INDEX ValueIndex, PDWORD Type, PBYTE Value, DWORD ValueLength, 
    PDWORD ResultLength
)
{
    SwapTibs();

    DebugPrint("ExQueryNonVolatileSetting: %i ...", ValueIndex);

    NTSTATUS Res = STATUS_SUCCESS;

    switch(ValueIndex)
    {
    case XC_LANGUAGE:
        *(DWORD *)Value = 1; // English
        break;
    case XC_AUDIO_FLAGS:
        *(DWORD *)Value = 0; // Stereo, no AC3, no DTS
        break;
    case XC_PARENTAL_CONTROL_GAMES:
        *(DWORD *)Value = 0; // No restrictions
        break;
    case XC_MISC_FLAGS:
        *(DWORD *)Value = 0; // No automatic power down
        break;
    case XC_MAX_OS:
        Res = STATUS_UNSUCCESSFUL;
        break;
    default:
        Res = STATUS_UNSUCCESSFUL;
    }

    SwapTibs();
    return Res;
}

DWORD WINAPI Dirtbox::HalGetInterruptVector(
    DWORD BusInterruptLevel, PKIRQL Irql
)
{
    SwapTibs();

    DebugPrint("HalGetInterruptVector: 0x%x 0x%08x", 
        BusInterruptLevel, Irql);

    DWORD result;
    result = BusInterruptLevel + 48;
    if ((BusInterruptLevel + 48) < 0x30 || result > 0x4A)
        result = 0;
    else
        *Irql = 74 - (KIRQL)result;

    SwapTibs();
    return result;
}

VOID WINAPI Dirtbox::HalReadWritePCISpace(
    DWORD BusNumber, DWORD SlotNumber, DWORD RegisterNumber, PVOID Buffer, 
    DWORD Length, BOOLEAN WritePCISpace
)
{
    SwapTibs();

    DebugPrint("HalReadWritePCISpace: 0x%x 0x%x 0x%x 0x%08x %i %i", 
        BusNumber, SlotNumber, RegisterNumber, Buffer, Length, WritePCISpace);

    if (!WritePCISpace) // read
    {
        PBYTE c = (PBYTE)Buffer;
        for (DWORD i = 0; i < Length; i++)
            c[i] = 0;
    }

    SwapTibs();
}

VOID WINAPI Dirtbox::HalRegisterShutdownNotification(
    PHAL_SHUTDOWN_REGISTRATION ShutdownRegistration, CHAR Register
)
{
    SwapTibs();

    DebugPrint("HalRegisterShutdownNotification: 0x%08x 0x%x", 
        ShutdownRegistration, Register);

    SwapTibs();
}

VOID WINAPI Dirtbox::HalReturnToFirmware(
    RETURN_FIRMWARE Routine
)
{
    SwapTibs();

    DebugPrint("HalReturnToFirmware: 0x%x", 
        Routine);

    FreeTib();
    exit(0);
}

PIRP WINAPI Dirtbox::IoBuildSynchronousFsdRequest(
    DWORD MajorFunction, PDEVICE_OBJECT DeviceObject, PVOID Buffer, DWORD Length, 
    PLARGE_INTEGER StartingOffset, PKEVENT Event, PIO_STATUS_BLOCK IoStatusBlock
)
{
    SwapTibs();

    DebugPrint("IoBuildSynchronousFsdRequest: 0x%x 0x%08x 0x%08x 0x%x 0x%08x 0x%08x 0x%08x", 
        MajorFunction, DeviceObject, Buffer, Length, StartingOffset, Event, IoStatusBlock);

    SwapTibs();
    return NULL;
}

NTSTATUS WINAPI Dirtbox::IoCreateDevice(
    PDRIVER_OBJECT DriverObject, DWORD DeviceExtensionSize, PANSI_STRING DeviceName, 
    DWORD DeviceType, BOOLEAN Exclusive, PDEVICE_OBJECT *DeviceObject
)
{
    SwapTibs();

    DebugPrint("IoCreateDevice: 0x%08x 0x%x \"%s\" 0x%x %i 0x%08x", 
        DriverObject, DeviceExtensionSize, DeviceName->Buffer, DeviceType, 
        Exclusive, DeviceObject);

    SwapTibs();
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS WINAPI Dirtbox::IoCreateSymbolicLink(
    PANSI_STRING SymbolicLinkName,
    PANSI_STRING DeviceName
)
{
    SwapTibs();

    DebugPrint("IoCreateSymbolicLink: \"%s\" \"%s\"", 
        SymbolicLinkName->Buffer, DeviceName->Buffer);

    // We can ignore this so far, since DOS drives created already.

    SwapTibs();
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI Dirtbox::IoDeleteSymbolicLink(
    PANSI_STRING SymbolicLinkName
)
{
    SwapTibs();

    DebugPrint("IoDeleteSymbolicLink: \"%s\"", 
        SymbolicLinkName->Buffer);

    // We can ignore this so far, since DOS drives created already.

    SwapTibs();
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI Dirtbox::IoInvalidDeviceRequest(
    PDEVICE_OBJECT DeviceObject, PIRP Irp
)
{
    SwapTibs();

    DebugPrint("IoInvalidDeviceRequest: 0x%08x 0x%08x", DeviceObject, Irp);

    SwapTibs();
    return STATUS_UNSUCCESSFUL;
}

VOID WINAPI Dirtbox::IoStartNextPacket(
    PDEVICE_OBJECT DeviceObject
)
{
    SwapTibs();

    DebugPrint("IoStartNextPacket: 0x%08x", DeviceObject);

    SwapTibs();
}

VOID WINAPI Dirtbox::IoStartPacket(
    PDEVICE_OBJECT DeviceObject, PIRP Irp, PDWORD Key
)
{
    SwapTibs();

    DebugPrint("IoStartPacket: 0x%08x 0x%08x 0x%08x", DeviceObject, Irp, Key);

    SwapTibs();
}

NTSTATUS WINAPI Dirtbox::IoSynchronousDeviceIoControlRequest(
    DWORD IoControlCode, PDEVICE_OBJECT DeviceObject, 
    PVOID InputBuffer, DWORD InputBufferLength, PVOID OutputBuffer, DWORD OutputBufferLength, 
    PDWORD ReturnedOutputBufferLength, CHAR InternalDeviceIoControl
)
{
    SwapTibs();

    DebugPrint("IoSynchronousDeviceIoControlRequest: 0x%x 0x%08x 0x%08x 0x%x 0x%08x 0x%x" 
        "0x%08x %i", 
        IoControlCode, DeviceObject, InputBuffer, InputBufferLength, 
        OutputBuffer, OutputBufferLength, ReturnedOutputBufferLength, InternalDeviceIoControl);

    SwapTibs();
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS WINAPI Dirtbox::IoSynchronousFsdRequest(
    DWORD MajorFunction, PDEVICE_OBJECT DeviceObject, PVOID Buffer, DWORD Length, 
    PLARGE_INTEGER StartingOffset
)
{
    SwapTibs();

    DebugPrint("IoSynchronousFsdRequest: 0x%x 0x%08x 0x%08x 0x%x 0x%08x", 
        MajorFunction, DeviceObject, Buffer, Length, StartingOffset);

    SwapTibs();
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS __fastcall Dirtbox::IofCallDriver(
    PDEVICE_OBJECT DeviceObject, PIRP Irp
)
{
    SwapTibs();

    DebugPrint("IofCallDriver: 0x%08x 0x%08x", DeviceObject, Irp);

    SwapTibs();
    return STATUS_UNSUCCESSFUL;
}

VOID __fastcall Dirtbox::IofCompleteRequest(
    PIRP Irp, CHAR PriorityBoost
)
{
    SwapTibs();

    DebugPrint("IofCompleteRequest: 0x%08x %i", Irp, PriorityBoost);

    SwapTibs();
}

VOID WINAPI Dirtbox::KeBugCheck(
    DWORD BugCheckCode
)
{
    SwapTibs();

    FatalPrint("KeBugCheck: %i", 
        BugCheckCode);
}

BOOLEAN WINAPI Dirtbox::KeConnectInterrupt(
    PKINTERRUPT Interrupt
)
{
    SwapTibs();

    DebugPrint("KeConnectInterrupt: %i %i %i %i %i %i",
        Interrupt->BusInterruptLevel, Interrupt->Irql, 
        Interrupt->Connected, Interrupt->ShareVector, 
        Interrupt->Mode, Interrupt->ServiceCount);

    if (Interrupt->Connected)
    {
        SwapTibs();
        return FALSE;
    }

    Interrupt->Connected = 1;

    SwapTibs();
    return TRUE;
}

NTSTATUS WINAPI Dirtbox::KeDelayExecutionThread(
    CHAR WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Interval
)
{
    SwapTibs();

    DebugPrint("KeDelayExecutionThread: %i %i 0x%08x", 
        WaitMode, Alertable, Interval);

    NTSTATUS Ret = ::NtDelayExecution(Alertable, Interval);

    SwapTibs();
    return Ret;
}

BOOLEAN WINAPI Dirtbox::KeDisconnectInterrupt(
    PKINTERRUPT Interrupt
)
{
    SwapTibs();
    DebugPrint("KeDisconnectInterrupt: 0x%08x 0x%08x %i %i %i %i %i %i",
        Interrupt->ServiceRoutine, Interrupt->ServiceContext,
        Interrupt->BusInterruptLevel, Interrupt->Irql, 
        Interrupt->Connected, Interrupt->ShareVector, 
        Interrupt->Mode, Interrupt->ServiceCount);

    if (!Interrupt->Connected)
    {
        SwapTibs();
        return FALSE;
    }

    Interrupt->Connected = 0;

    SwapTibs();
    return TRUE;
}

VOID WINAPI Dirtbox::KeInitializeDpc(
    PKDPC Dpc, PKDEFERRED_ROUTINE DeferredRoutine, PVOID DeferredContext
)
{
    SwapTibs();

    DebugPrint("KeInitializeDpc: 0x%08x 0x%08x 0x%08x",
        Dpc, DeferredRoutine, DeferredContext);

    Dpc->DeferredRoutine = DeferredRoutine;
    Dpc->Type = DpcObject;
    Dpc->DeferredContext = DeferredContext;
    Dpc->Inserted = 0;

    SwapTibs();
}

VOID WINAPI Dirtbox::KeInitializeInterrupt(
    PKINTERRUPT Interrupt, PKSERVICE_ROUTINE ServiceRoutine, PVOID ServiceContext, DWORD Vector,
    KIRQL Irql, KINTERRUPT_MODE InterruptMode, BOOLEAN ShareVector
)
{
    SwapTibs();

    DebugPrint("KeInitializeInterrupt: 0x%08x 0x%08x %i %i %i %i",
        ServiceRoutine, ServiceContext, Vector, Irql, InterruptMode, ShareVector);

    Interrupt->ServiceRoutine = ServiceRoutine;
    Interrupt->Irql = Irql;
    Interrupt->ServiceContext = ServiceContext;
    Interrupt->BusInterruptLevel = Vector - 48;
    Interrupt->Mode = InterruptMode;
    Interrupt->Connected = 0;

    SwapTibs();
}

VOID WINAPI Dirtbox::KeInitializeTimerEx(
    PKTIMER Timer, TIMER_TYPE Type
)
{
    SwapTibs();

    DebugPrint("KeInitializeTimerEx: %i %i 0x%08x", 
        Timer, Type);

    Timer->Header.Type = TimerNotificationObject + Type;
    Timer->Header.Inserted = 0;
    Timer->Header.Size = sizeof(KTIMER)/4;
    Timer->Header.SignalState = 0;
    Timer->Header.WaitListHead.Blink = &Timer->Header.WaitListHead;
    Timer->Header.WaitListHead.Flink = &Timer->Header.WaitListHead;
    Timer->DueTime.QuadPart = 0L;
    Timer->Period = 0;

    SwapTibs();
}

BOOLEAN WINAPI Dirtbox::KeInsertQueueDpc(
    PKDPC Dpc, PVOID SystemArgument1, PVOID SystemArgument2
)
{
    SwapTibs();

    DebugPrint("KeInsertQueueDpc: %i %i 0x%08x 0x%08x",
        Dpc->Type, Dpc->Inserted, SystemArgument1, SystemArgument2);

    if (Dpc->Inserted)
    {
        SwapTibs();
        return FALSE;
    }

    Dpc->SystemArgument1 = SystemArgument1;
    Dpc->SystemArgument2 = SystemArgument2;
    Dpc->Inserted = 1;

    SwapTibs();
    return TRUE;
}

VOID WINAPI Dirtbox::KeQuerySystemTime(
    PLARGE_INTEGER CurrentTime
)
{
    SwapTibs();

    DebugPrint("KeQuerySystemTime: 0x%08x",
        CurrentTime);

    SYSTEMTIME SystemTime;
    GetSystemTime(&SystemTime);
    SystemTimeToFileTime(&SystemTime, (FILETIME*)CurrentTime);

    SwapTibs();
}

KIRQL WINAPI Dirtbox::KeRaiseIrqlToDpcLevel()
{
    PKPCR Kpcr;
    __asm
    {
        mov eax, fs:[0x1C]
        mov Kpcr, eax
    }

    SwapTibs();

    DebugPrint("KeRaiseIrqlToDpcLevel");

    KIRQL OldIrql = (KIRQL)Kpcr->Irql;
    Kpcr->Irql = 2;

    SwapTibs();
    return OldIrql;
}

BOOLEAN WINAPI Dirtbox::KeSetEvent(
    PKEVENT Event, LONG Increment, CHAR Wait
)
{
    SwapTibs();

    DebugPrint("KeSetEvent: 0x%08x %i %i",
        Event, Increment, Wait);

    // thinking of how to implement Ke events with the Windows API event objects.
    // maybe a hash table of addresses of KEVENT objects?
    if (Event->Header.Type != 0)
        FatalPrint("KeSetEvent: Events other than Notification Events not implemented.");

    if (Event->Header.WaitListHead.Flink != &Event->Header.WaitListHead)
        FatalPrint("KeSetEvent: Events with more than two threads not supported.");

    Event->Header.SignalState = 1;

    SwapTibs();
    return TRUE;
}

BOOLEAN WINAPI Dirtbox::KeSetTimer(
    PKTIMER Timer, LARGE_INTEGER DueTime, PKDPC Dpc
)
{
    SwapTibs();

    DebugPrint("KeSetTimer: 0x%08x 0x%08x 0x%08x",
        Timer, DueTime, Dpc);

    // Don't really need to implement it yet, only used in shutdown
    Timer->Header.SignalState = 0;
    Timer->Period = 0;
    Timer->Dpc = Dpc;

    SwapTibs();
    return TRUE;
}

NTSTATUS WINAPI Dirtbox::KeWaitForSingleObject(
    PVOID Object, KWAIT_REASON WaitReason, CHAR WaitMode, CHAR Alertable, 
    PLARGE_INTEGER Timeout
)
{
    SwapTibs();

    DebugPrint("KeWaitForSingleObject: 0x%08x %i %i %i %i 0x%08x",
        Object, WaitReason, WaitMode, Alertable, Timeout);

    // Loop disabled since we don't signal the VBlank object

    /*
    while (((PKEVENT)Object)->Header.SignalState == 0)
        ;
    */

    SwapTibs();
    return STATUS_SUCCESS;
}

DWORD __fastcall Dirtbox::KfLowerIrql(KIRQL NewIrql)
{
    PKPCR Kpcr;
    __asm
    {
        mov eax, fs:[0x1C]
        mov Kpcr, eax
    }

    SwapTibs();

    DebugPrint("KfLowerIrql: %i", NewIrql);

    Kpcr->Irql = NewIrql;

    SwapTibs();
    return 0;
}

PVOID WINAPI Dirtbox::MmAllocateContiguousMemory(
    DWORD NumberOfBytes
)
{
    return MmAllocateContiguousMemoryEx(NumberOfBytes, 0, 0xFFFFFFFF, 0, PAGE_READWRITE);
}

PVOID WINAPI Dirtbox::MmAllocateContiguousMemoryEx(
    DWORD NumberOfBytes, DWORD LowestAcceptableAddress, DWORD HighestAcceptableAddress,
    DWORD Alignment, DWORD ProtectionType
)
{
    SwapTibs();

    DebugPrint("MmAllocateContiguousMemoryEx: 0x%x 0x%08x 0x%08x 0x%x 0x%08x",
        NumberOfBytes, LowestAcceptableAddress, HighestAcceptableAddress, Alignment, ProtectionType);

    if ((Alignment - 1) & Alignment)
    {
        DebugPrint("MmAllocateContiguousMemoryEx: alignment not power of 2");
        return NULL;
    }
    if (Alignment == 0)
        Alignment = 0x1000;

    DWORD AlignmentMask = ~(Alignment - 1);
    PVOID Buf;
    DWORD StartAddress;
    DWORD EndAddress;
    if (HighestAcceptableAddress == 0xFFFFFFFF)
        EndAddress = 0x83FD6000;
    else
        EndAddress = HighestAcceptableAddress | 0x80000000;
    ProtectionType &= ~PAGE_WRITECOMBINE;

    while (TRUE)
    {
        StartAddress = (EndAddress - NumberOfBytes) & AlignmentMask;
        if (StartAddress < (LowestAcceptableAddress | 0x80000000))
            break;
        Buf = VirtualAlloc(
            (PVOID)StartAddress, NumberOfBytes, MEM_COMMIT | MEM_RESERVE, ProtectionType
        );
        EndAddress -= Alignment;
        if (Buf != NULL)
            break;
    }

    SwapTibs();
    return Buf;
}

PVOID WINAPI Dirtbox::MmClaimGpuInstanceMemory(
    DWORD NumberOfBytes, PDWORD NumberOfPaddingBytes
)
{
    SwapTibs();

    DebugPrint("MmClaimGpuInstanceMemory: 0x%x 0x%08x",
        NumberOfBytes, NumberOfPaddingBytes);

    *NumberOfPaddingBytes = PADDING_SIZE;
    if (NumberOfBytes == 0xFFFFFFFF)
        NumberOfBytes = GPU_INST_SIZE;

    // A hack since we're not actually returning the memory at the
    // end of physical space, but the "virtual GPU memory address."
    // Hence why I selected as 0x84000000 as new register base.
    DWORD Res = REGISTER_BASE + NV_GPU_INST + PADDING_SIZE + GPU_INST_SIZE;

    SwapTibs();
    return (PVOID)Res;
}

VOID WINAPI Dirtbox::MmFreeContiguousMemory(
    PVOID BaseAddress
)
{
    SwapTibs();

    DebugPrint("MmFreeContiguousMemory: 0x%08x",
        BaseAddress);

    VirtualFree(BaseAddress, 0, MEM_RELEASE);

    SwapTibs();
}

VOID WINAPI Dirtbox::MmPersistContiguousMemory(
    PVOID BaseAddress, DWORD NumberOfBytes, BOOLEAN Persist
)
{
    SwapTibs();

    DebugPrint("MmPersistContiguousMemory: 0x%08x 0x%x %i",
        BaseAddress, NumberOfBytes, Persist);

    // Not sure if we need to implement this

    SwapTibs();
}

DWORD WINAPI Dirtbox::MmQueryAddressProtect(
    PVOID VirtualAddress
)
{
    SwapTibs();

    DebugPrint("MmQueryAddressProtect: 0x%08x",
        VirtualAddress);

    MEMORY_BASIC_INFORMATION MemInfo;
    VirtualQuery(VirtualAddress, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION));

    SwapTibs();
    return MemInfo.Protect;
}

DWORD WINAPI Dirtbox::MmQueryAllocationSize(
    PVOID BaseAddress
)
{
    SwapTibs();

    DebugPrint("MmQueryAllocationSize: 0x%08x",
        BaseAddress);

    MEMORY_BASIC_INFORMATION MemInfo;
    VirtualQuery(BaseAddress, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION));

    SwapTibs();
    return MemInfo.RegionSize;
}

DWORD WINAPI Dirtbox::MmSetAddressProtect(
    PVOID BaseAddress, DWORD NumberOfBytes, DWORD NewProtect
)
{
    SwapTibs();

    DebugPrint("MmSetAddressProtect: 0x%08x 0x%x 0x%08x",
        BaseAddress, NumberOfBytes, NewProtect);

    DWORD Dummy;
    DWORD Res = VirtualProtect(BaseAddress, NumberOfBytes, NewProtect, &Dummy);

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtAllocateVirtualMemory(
    PVOID *BaseAddress, DWORD ZeroBits, PDWORD AllocationSize, DWORD AllocationType,
    DWORD Protect
)
{
    SwapTibs();

    DebugPrint("NtAllocateVirtualMemory: 0x%08x 0x%x 0x%x 0x%x 0x%x",
        BaseAddress, ZeroBits, *AllocationSize, AllocationType, Protect);

    NTSTATUS Res = ::NtAllocateVirtualMemory(
        GetCurrentProcess(), BaseAddress, ZeroBits, AllocationSize, 
        AllocationType, Protect);

    DebugPrint("Returned: 0x%08x", Res);
    
    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtClose(
    HANDLE Handle
)
{
    SwapTibs();

    DebugPrint("NtClose: 0x%x",
        Handle);

    NTSTATUS Res = ::NtClose(Handle);

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtCreateFile(
    PHANDLE FileHandle, DWORD DesiredAccess, PXBOX_OBJECT_ATTRIBUTES ObjectAttributes, 
    PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, DWORD FileAttributes, 
    DWORD ShareAccess, DWORD CreateDisposition, DWORD CreateOptions 
)
{
    SwapTibs();

    DebugPrint("NtCreateFile: 0x%08x 0x%x 0x%08x \"%s\" 0x%08x 0x%08x 0x%x 0x%x 0x%x 0x%x",
        FileHandle, DesiredAccess, ObjectAttributes, ObjectAttributes->ObjectName->Buffer, 
        IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, 
        CreateDisposition, CreateOptions);

    OBJECT_ATTRIBUTES NtObjectAttributes;
    UNICODE_STRING ObjectName;
    WCHAR Buffer[MAX_PATH];
    NTSTATUS Res = ConvertObjectAttributes(
        &NtObjectAttributes, &ObjectName, Buffer, ObjectAttributes
    );
    if (!NT_SUCCESS(Res))
    {
        SwapTibs();
        return Res;
    }

    // Call Windows NT equivalent
    Res = ::NtCreateFile(
        FileHandle, DesiredAccess, &NtObjectAttributes, IoStatusBlock, AllocationSize, 
        FileAttributes, ShareAccess, CreateDisposition, CreateOptions, NULL, 0
    );

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtDeviceIoControlFile(
    HANDLE FileHandle, PKEVENT Event, PVOID ApcRoutine, PVOID ApcContext, 
    PIO_STATUS_BLOCK IoStatusBlock, DWORD IoControlCode, PVOID InputBuffer, DWORD InputBufferLength, 
    PVOID OutputBuffer, DWORD OutputBufferLength)
{
    SwapTibs();

    DebugPrint("NtDeviceIoControlFile: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%x " 
        "0x%08x 0x%x 0x%08x 0x%x",
        FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength,
        OutputBuffer, OutputBufferLength);

    // TODO: not needed unless mounting utility drive

    SwapTibs();
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS WINAPI Dirtbox::NtFlushBuffersFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock
)
{
    SwapTibs();

    DebugPrint("NtFlushBuffersFile: 0x%08x 0x%08x", 
        FileHandle, IoStatusBlock);

    DWORD Res = ::NtFlushBuffersFile(FileHandle, IoStatusBlock);

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtFreeVirtualMemory(
    PVOID *BaseAddress, PDWORD FreeSize, DWORD FreeType
)
{
    SwapTibs();

    DebugPrint("NtFreeVirtualMemory: 0x%08x 0x%08x 0x%x", 
        BaseAddress, FreeSize, FreeType);

    NTSTATUS Res = ::NtFreeVirtualMemory(
        GetCurrentProcess(), BaseAddress, FreeSize, FreeType
    );

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtFsControlFile(
    HANDLE FileHandle, PKEVENT Event, PVOID ApcRoutine, PVOID ApcContext, 
    PIO_STATUS_BLOCK IoStatusBlock, DWORD IoControlCode, PVOID InputBuffer, DWORD InputBufferLength, 
    PVOID OutputBuffer, DWORD OutputBufferLength
)
{
    SwapTibs();

    DebugPrint("NtFsControlFile: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%x " 
        "0x%08x 0x%x 0x%08x 0x%x",
        FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength,
        OutputBuffer, OutputBufferLength);

    // TODO: not needed unless mounting utility drive

    SwapTibs();
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS WINAPI Dirtbox::NtOpenFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess, PXBOX_OBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, DWORD ShareAccess, DWORD OpenOptions
)
{
    SwapTibs();

    DebugPrint("NtOpenFile: 0x%08x 0x%x 0x%08x \"%s\" 0x%08x 0x%x 0x%x",
        FileHandle, DesiredAccess, ObjectAttributes, ObjectAttributes->ObjectName->Buffer, 
        IoStatusBlock, ShareAccess, OpenOptions);

    OBJECT_ATTRIBUTES NtObjectAttributes;
    UNICODE_STRING ObjectName;
    WCHAR Buffer[MAX_PATH];
    NTSTATUS Res = ConvertObjectAttributes(
        &NtObjectAttributes, &ObjectName, Buffer, ObjectAttributes
    );
    if (!NT_SUCCESS(Res))
    {
        SwapTibs();
        return Res;
    }

    // Call Windows NT equivalent
    Res = ::NtOpenFile(
        FileHandle, DesiredAccess, &NtObjectAttributes, IoStatusBlock, 
        ShareAccess, OpenOptions
    );

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtOpenSymbolicLinkObject(
    PHANDLE LinkHandle, PXBOX_OBJECT_ATTRIBUTES ObjectAttributes
)
{
    SwapTibs();

    DebugPrint("NtOpenSymbolicLinkObject: 0x%08x 0x%08x \"%s\"",
        LinkHandle, ObjectAttributes, ObjectAttributes->ObjectName->Buffer);

    // Can fail, then it assumes to be CD-ROM

    SwapTibs();
    return -1;
}

NTSTATUS WINAPI Dirtbox::NtQueryInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, DWORD Length, 
    FILE_INFORMATION_CLASS FileInformationClass
)
{
    SwapTibs();

    DebugPrint("NtQueryInformationFile: 0x%08x 0x%08x 0x%08x 0x%x 0x%x",
        FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);

    DWORD Res = ::NtQueryInformationFile(
        FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass
    );

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtQuerySymbolicLinkObject(
    HANDLE LinkHandle, PANSI_STRING LinkTarget, PDWORD ReturnedLength
)
{
    SwapTibs();

    DebugPrint("NtOpenSymbolicLinkObject: 0x%08x \"%s\" 0x%x",
        LinkHandle, LinkTarget->Buffer, ReturnedLength);

    // Can fail, then it assumes to be CD-ROM

    SwapTibs();
    return -1;
}

NTSTATUS WINAPI Dirtbox::NtQueryVirtualMemory(
    PVOID BaseAddress, PMEMORY_BASIC_INFORMATION MemoryInformation
)
{
    SwapTibs();

    DebugPrint("NtQueryVirtualMemory: 0x%08x 0x%08x",
        BaseAddress, MemoryInformation);

    NTSTATUS Res = VirtualQuery(
        BaseAddress, MemoryInformation, sizeof(MEMORY_BASIC_INFORMATION)
    );

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtQueryVolumeInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation, DWORD Length, 
    FS_INFORMATION_CLASS FsInformationClass
)
{
    SwapTibs();

    DebugPrint("NtQueryVolumeInformationFile: 0x%08x 0x%08x 0x%08x 0x%x 0x%08x",
        FileHandle, IoStatusBlock, FsInformation, Length, FsInformationClass);

    DWORD Res = ::NtQueryVolumeInformationFile(
        FileHandle, IoStatusBlock, FsInformation, Length, FsInformationClass
    );

    if (FsInformationClass == FileFsSizeInformation)
    {
        PFILE_FS_SIZE_INFORMATION Fs = (PFILE_FS_SIZE_INFORMATION)FsInformation;
        // fucking magic over here, product has to equal 0x4000
        Fs->SectorsPerAllocationUnit = 4;
        Fs->BytesPerSector = 0x1000;
    }

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtReadFile(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, DWORD Length, PLARGE_INTEGER ByteOffset
)
{
    SwapTibs();

    DebugPrint("NtReadFile: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%x 0x%08x",
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset);

    NTSTATUS Res = ::NtReadFile(
        FileHandle, Event, NULL, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, NULL
    );

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtSetInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, DWORD Length, 
    DWORD FileInformationClass
)
{
    SwapTibs();

    DebugPrint("NtSetInformationFile: 0x%08x 0x%08x 0x%08x 0x%x 0x%x",
        FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);

    NTSTATUS Res = ::NtSetInformationFile(
        FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass
    );

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtWaitForSingleObject(
    HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout
)
{
    return NtWaitForSingleObjectEx(Handle, 0, Alertable, Timeout);
}

NTSTATUS WINAPI Dirtbox::NtWaitForSingleObjectEx(
    HANDLE Handle, CHAR WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout
)
{
    SwapTibs();

    DebugPrint("NtWaitForSingleObjectEx: 0x%08x 0x%x %i 0x%08x",
        Handle, WaitMode, Alertable, Timeout);

    NTSTATUS Res = ::NtWaitForSingleObject(
        Handle, Alertable, Timeout
    );

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtWriteFile( 
    HANDLE FileHandle, PVOID Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, DWORD Length, PLARGE_INTEGER ByteOffset
)
{
    SwapTibs();

    DebugPrint("NtWriteFile: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%x 0x%08x",
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset);

    NTSTATUS Res = ::NtWriteFile(
        FileHandle, Event, NULL, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, NULL
    );

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::PsCreateSystemThreadEx(
    PHANDLE ThreadHandle, DWORD ThreadExtensionSize, DWORD KernelStackSize, DWORD TlsDataSize, 
    PDWORD ThreadId, PKSTART_ROUTINE StartRoutine, PVOID StartContext, BOOLEAN CreateSuspended, 
    BOOLEAN DebuggerThread, PKSYSTEM_ROUTINE SystemRoutine
)
{
    SwapTibs();

    DebugPrint("PsCreateSystemThreadEx: 0x%08x 0x%x 0x%x 0x%x 0x%08x "
        "0x%08x 0x%08x %i %i 0x%08x",
        ThreadHandle, ThreadExtensionSize, KernelStackSize, TlsDataSize, ThreadId, 
        StartRoutine, StartContext, CreateSuspended, DebuggerThread, SystemRoutine);

    PSHIM_CONTEXT ShimContext = (PSHIM_CONTEXT)malloc(sizeof(SHIM_CONTEXT));
    if (ShimContext == NULL)
    {
        SwapTibs();
        DebugPrint("PsCreateSystemThreadEx: failed to allocate shim context.");
        return STATUS_UNSUCCESSFUL;
    }

    ShimContext->TlsDataSize = TlsDataSize;
    ShimContext->StartRoutine = StartRoutine;
    ShimContext->StartContext = StartContext;
    ShimContext->SystemRoutine = SystemRoutine;

    DWORD Flags = CreateSuspended ? CREATE_SUSPENDED : 0;

    /*
    Is it better to use _beginthreadex, CreateThread, or NtCreateThread?
    */
    HANDLE Thr = (HANDLE)_beginthreadex(
        NULL, KernelStackSize + 0x1000, &ShimCallback, ShimContext, Flags, NULL
    );
    if (Thr == 0)
    {
        free(ShimContext);
        SwapTibs();
        return STATUS_UNSUCCESSFUL;
    }

    *ThreadHandle = Thr;
    SwapTibs();
    return STATUS_SUCCESS;
}

VOID WINAPI Dirtbox::PsTerminateSystemThread(
    NTSTATUS ExitStatus
)
{
    SwapTibs();

    DebugPrint("PsTerminateSystemThread: %i", ExitStatus);
    
    // like the same thing as in ShimCallback
    FreeTib();

    _endthreadex(ExitStatus);
}

SIZE_T WINAPI Dirtbox::RtlCompareMemoryUlong(
    PVOID Source, SIZE_T Length, DWORD Pattern
)
{
    SwapTibs();

    DebugPrint("RtlCompareMemoryUlong: 0x%08x 0x%x 0x%x", Source, Length, Pattern);

    SIZE_T Res = ::RtlCompareMemoryUlong(Source, Length, Pattern);

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::RtlEnterCriticalSection(
    PXBOX_CRITICAL_SECTION CriticalSection
)
{
    PKPCR Kpcr = (PKPCR)__readfsdword(KPCR_SELF_PCR);

    SwapTibs();

    DebugPrint("RtlEnterCriticalSection: 0x%08x", CriticalSection);

    // has critical section already been acquired yet?
    if (InterlockedIncrement(&CriticalSection->LockCount) == 0)
    {
        // we are the first to acquire the critical section
    }
    else if (CriticalSection->OwningThread == Kpcr->Prcb->CurrentThread)
    {
        // critical section has been acquired already, but by same thread
        CriticalSection->RecursionCount++;
        SwapTibs();
        return STATUS_SUCCESS;
    }
    else
    {
        // critical section has been acquired already, by different thread
        while (InterlockedExchange(&CriticalSection->Synchronization.SignalState, 0) != 1) ;
    }

    CriticalSection->RecursionCount = 1;
    CriticalSection->OwningThread = Kpcr->Prcb->CurrentThread;
    SwapTibs();
    return STATUS_SUCCESS;
}

LONG WINAPI Dirtbox::RtlEqualString(
    PANSI_STRING String1, PANSI_STRING String2, BOOLEAN CaseInSensitive
)
{
    SwapTibs();

    DebugPrint("RtlEqualString:  \"%s\" \"%s\" %i", 
        String1->Buffer, String2->Buffer, CaseInSensitive);

    LONG Res = ::RtlEqualString(String1, String2, CaseInSensitive);

    SwapTibs();
    return Res;
}

VOID WINAPI Dirtbox::RtlInitAnsiString(
    PANSI_STRING DestinationString, PSTR SourceString
)
{
    SwapTibs();

    DebugPrint("RtlInitAnsiString: 0x%08x \"%s\"", DestinationString, SourceString);

    ::RtlInitAnsiString(DestinationString, SourceString);

    SwapTibs();
}

VOID WINAPI Dirtbox::RtlInitializeCriticalSection(
    PXBOX_CRITICAL_SECTION CriticalSection
)
{
    SwapTibs();

    DebugPrint("RtlInitializeCriticalSection: 0x%08x", CriticalSection);

    CriticalSection->Synchronization.Type = EventSynchronizationObject;
    CriticalSection->Synchronization.Size = sizeof(DISPATCHER_HEADER)/4;
    CriticalSection->Synchronization.SignalState = 0;
    CriticalSection->Synchronization.WaitListHead.Blink = 
        &CriticalSection->Synchronization.WaitListHead;
    CriticalSection->Synchronization.WaitListHead.Flink = 
        &CriticalSection->Synchronization.WaitListHead;

    CriticalSection->LockCount = -1;
    CriticalSection->RecursionCount = 0;
    CriticalSection->OwningThread = NULL;

    SwapTibs();
}

VOID WINAPI Dirtbox::RtlLeaveCriticalSection(
    PXBOX_CRITICAL_SECTION CriticalSection
)
{
    SwapTibs();

    DebugPrint("RtlLeaveCriticalSection: 0x%08x", CriticalSection);

    // is this the last release of critical section in this thread?
    CriticalSection->RecursionCount--;
    if (CriticalSection->RecursionCount > 0)
    {
        InterlockedDecrement(&CriticalSection->LockCount);
    }
    else
    {
        // this thread no longer holds this critical section
        CriticalSection->OwningThread = NULL;
        // are there other threads waiting on this critical section?
        if (InterlockedDecrement(&CriticalSection->LockCount) > -1)
        {
            // signal to other threads waiting on critical section
            CriticalSection->Synchronization.SignalState = 1;
        }
    }


    SwapTibs();
}

DWORD WINAPI Dirtbox::RtlNtStatusToDosError(
    NTSTATUS Status
)
{
    SwapTibs();

    DebugPrint("RtlNtStatusToDosError: 0x%x", Status);

    DWORD Res = ::RtlNtStatusToDosError(Status);

    SwapTibs();
    return Res;
}

VOID WINAPI Dirtbox::RtlRaiseException(
    PEXCEPTION_RECORD ExceptionRecord
)
{
    SwapTibs();


    DebugPrint("RtlRaiseException: 0x%08x", ExceptionRecord);

    // WARNING! WE MAY NEED TO COPY STUFF FROM XBOX TIB INTO NT TIB!
    ::RtlRaiseException(ExceptionRecord);

    SwapTibs();
}

VOID WINAPI Dirtbox::RtlUnwind(
    PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue
)
{
    SwapTibs();

    DebugPrint("RtlUnwind: 0x%08x 0x%08x 0x%08x 0x%08x", 
        TargetFrame, TargetIp, ExceptionRecord, ReturnValue);

    // WARNING! WE MAY NEED TO COPY STUFF FROM XBOX TIB INTO NT TIB!
    ::RtlUnwind(TargetFrame, TargetIp, ExceptionRecord, ReturnValue);

    SwapTibs();
}

NTSTATUS WINAPI Dirtbox::XeLoadSection(
    PXBEIMAGE_SECTION Section
)
{
    SwapTibs();

    DebugPrint("XeLoadSection: 0x%08x", Section);

    // don't need to load on-demand sections yet

    SwapTibs();
    return 0;
}

NTSTATUS WINAPI Dirtbox::XeUnloadSection(
    PXBEIMAGE_SECTION Section
)
{
    SwapTibs();

    DebugPrint("XeUnloadSection: 0x%08x", Section);

    // don't need to load on-demand sections yet

    SwapTibs();
    return 0;
}

VOID WINAPI Dirtbox::XcSHAInit(
    PCHAR SHAContext
)
{
    SwapTibs();

    DebugPrint("XcSHAInit: 0x%08x", SHAContext);

    // don't nead crypto yet

    SwapTibs();
}

VOID WINAPI Dirtbox::XcSHAUpdate(
    PCHAR SHAContext, PCHAR Input, DWORD InputLength
)
{
    SwapTibs();

    DebugPrint("XcSHAUpdate: 0x%08x 0x%08x 0x%x", SHAContext, Input, InputLength);

    // don't nead crypto yet

    SwapTibs();
}

VOID WINAPI Dirtbox::XcSHAFinal(
    PCHAR SHAContext, PCHAR Digest
)
{
    SwapTibs();

    DebugPrint("XcSHAFinal: 0x%08x 0x%08x", SHAContext, Digest);

    // don't nead crypto yet

    SwapTibs();
}

VOID WINAPI Dirtbox::XcHMAC(
    PCHAR KeyMaterial, DWORD DwordKeyMaterial, PCHAR Data, DWORD DwordData, 
    PCHAR Data2, DWORD DwordData2, PCHAR Digest
)
{
    SwapTibs();

    DebugPrint("XcHMAC: 0x%08x 0x%x 0x%08x 0x%x 0x%08x 0x%x 0x%08x", 
        KeyMaterial, DwordKeyMaterial, Data, DwordData, Data2, DwordData2, Digest);

    // don't nead crypto yet

    SwapTibs();
}

VOID WINAPI Dirtbox::HalInitiateShutdown()
{
    SwapTibs();

    DebugPrint("HalInitiateShutdown");

    SwapTibs();
}