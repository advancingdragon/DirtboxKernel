// Emulated xboxkrnl.exe functions

#include "DirtboxEmulator.h"
#include "DirtboxKernel.h"
#include "Native.h"
#include <malloc.h>
#include <process.h>

namespace Dirtbox
{
    OBJECT_TYPE ExEventObjectType;
    DWORD HalDiskCachePartitionCount;
    KSYSTEM_TIME KeTickCount;
    DWORD LaunchDataPage;
    OBJECT_TYPE PsThreadObjectType;
    XBOX_HARDWARE_INFO XboxHardwareInfo;
    XBOX_KRNL_VERSION XboxKrnlVersion;
    DWORD HalBootSMCVideoMode;
    DWORD IdexChannelObject;

    PVOID AvpSavedDataAddress = (PVOID)0;
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

    DebugPrint("ExQueryNonVolatileSetting: %i 0x%08x 0x%08x 0x%x 0x%08x", 
        ValueIndex, Type, Value, ValueLength, ResultLength);

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

VOID WINAPI Dirtbox::KeBugCheck(
    DWORD BugCheckCode
)
{
    SwapTibs();

    FatalPrint("KeBugCheck: %i", BugCheckCode);
}

BOOLEAN WINAPI Dirtbox::KeCancelTimer(
    PKTIMER Timer
)
{
    SwapTibs();

    DebugPrint("KeCancelTimer: 0x%08x", Timer);

    BOOLEAN Res = CancelWaitableTimer(GetDirtObject(Timer));

    SwapTibs();
    return Res;
}

BOOLEAN WINAPI Dirtbox::KeConnectInterrupt(
    PKINTERRUPT Interrupt
)
{
    SwapTibs();

    DebugPrint("KeConnectInterrupt: 0x%08x", Interrupt);

    if (Interrupt->Connected)
    {
        SwapTibs();
        return FALSE;
    }

    Interrupt->Connected = TRUE;

    SwapTibs();
    return TRUE;
}

NTSTATUS WINAPI Dirtbox::KeDelayExecutionThread(
    KPROCESSOR_MODE WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Interval
)
{
    SwapTibs();

    DebugPrint("KeDelayExecutionThread: %i %i 0x%08x", WaitMode, Alertable, Interval);

    NTSTATUS Ret = ::NtDelayExecution(Alertable, Interval);

    SwapTibs();
    return Ret;
}

BOOLEAN WINAPI Dirtbox::KeDisconnectInterrupt(
    PKINTERRUPT Interrupt
)
{
    SwapTibs();
    DebugPrint("KeDisconnectInterrupt: 0x%08x", Interrupt);

    if (!Interrupt->Connected)
    {
        SwapTibs();
        return FALSE;
    }

    Interrupt->Connected = FALSE;

    SwapTibs();
    return TRUE;
}

VOID WINAPI Dirtbox::KeInitializeDpc(
    PKDPC Dpc, PKDEFERRED_ROUTINE DeferredRoutine, PVOID DeferredContext
)
{
    SwapTibs();

    DebugPrint("KeInitializeDpc: 0x%08x 0x%08x 0x%08x", Dpc, DeferredRoutine, DeferredContext);

    Dpc->DeferredRoutine = DeferredRoutine;
    Dpc->Type = DpcObject;
    Dpc->DeferredContext = DeferredContext;
    Dpc->Inserted = FALSE;

    SwapTibs();
}

VOID WINAPI Dirtbox::KeInitializeEvent(
    PKEVENT Event, EVENT_TYPE Type, BOOLEAN State
)
{
    SwapTibs();

    DebugPrint("KeInitializeEvent: 0x%08x %i %i", Event, Type, State);

    Event->Header.Type = Type;
    Event->Header.SignalState = State;
    Event->Header.Size = sizeof(KEVENT)/4;
    Event->Header.WaitListHead.Blink = &Event->Header.WaitListHead;
    Event->Header.WaitListHead.Flink = &Event->Header.WaitListHead;

    SwapTibs();
}

VOID WINAPI Dirtbox::KeInitializeInterrupt(
    PKINTERRUPT Interrupt, PKSERVICE_ROUTINE ServiceRoutine, PVOID ServiceContext, DWORD Vector,
    KIRQL Irql, KINTERRUPT_MODE InterruptMode, BOOLEAN ShareVector
)
{
    SwapTibs();

    DebugPrint("KeInitializeInterrupt: 0x%08x 0x%08x 0x%08x %i %i %i %i", 
        Interrupt, ServiceRoutine, ServiceContext, Vector, Irql, InterruptMode, ShareVector);

    Interrupt->ServiceRoutine = ServiceRoutine;
    Interrupt->Irql = Irql;
    Interrupt->ServiceContext = ServiceContext;
    Interrupt->BusInterruptLevel = Vector - 48;
    Interrupt->Mode = InterruptMode;
    Interrupt->Connected = FALSE;

    SwapTibs();
}

VOID WINAPI Dirtbox::KeInitializeTimerEx(
    PKTIMER Timer, TIMER_TYPE Type
)
{
    SwapTibs();

    DebugPrint("KeInitializeTimerEx: 0x%08x %i", Timer, Type);

    Timer->Header.Type = TimerNotificationObject + Type;
    Timer->Header.Inserted = FALSE;
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

    DebugPrint("KeInsertQueueDpc: 0x%08x 0x%08x 0x%08x", Dpc, SystemArgument1, SystemArgument2);

    if (Dpc->Inserted)
    {
        SwapTibs();
        return FALSE;
    }

    Dpc->SystemArgument1 = SystemArgument1;
    Dpc->SystemArgument2 = SystemArgument2;
    Dpc->Inserted = TRUE;

    SwapTibs();
    return TRUE;
}

KPRIORITY WINAPI Dirtbox::KeQueryBasePriorityThread(
    PKTHREAD Thread
)
{
    SwapTibs();

    DebugPrint("KeQueryBasePriorityThread: 0x%08x", Thread);

    // To get the "real" value, use NtQueryInformationThread

    KPRIORITY Res = Thread->BasePriority - 8; // 8 == System process's base priority
    if (Thread->Saturation)
        Res = Thread->Saturation * 16;

    SwapTibs();
    return Res;
}

DWORDLONG WINAPI Dirtbox::KeQueryInterruptTime()
{
    SwapTibs();

    DebugPrint("KeQueryInterruptTime");

    // Do we even need to implement this?

    SwapTibs();
    return 0L;
}

VOID WINAPI Dirtbox::KeQuerySystemTime(
    PLARGE_INTEGER CurrentTime
)
{
    SwapTibs();

    DebugPrint("KeQuerySystemTime: 0x%08x", CurrentTime);

    NtQuerySystemTime(CurrentTime);

    SwapTibs();
}

KIRQL WINAPI Dirtbox::KeRaiseIrqlToDpcLevel()
{
    PKPCR Kpcr = (PKPCR)__readfsdword(KPCR_SELF_PCR);
    SwapTibs();

    DebugPrint("KeRaiseIrqlToDpcLevel");

    KIRQL OldIrql = (KIRQL)Kpcr->Irql;
    Kpcr->Irql = 2;

    SwapTibs();
    return OldIrql;
}

BOOLEAN WINAPI Dirtbox::KeRemoveQueueDpc(
    PKDPC Dpc
)
{
    SwapTibs();

    DebugPrint("KeRemoveQueueDpc: 0x%08x", Dpc);

    if (!Dpc->Inserted)
    {
        SwapTibs();
        return FALSE;
    }

    // TODO the rest
    Dpc->Inserted = FALSE;

    SwapTibs();
    return TRUE;
}

NTSTATUS WINAPI Dirtbox::KeRestoreFloatingPointState(
    PKFLOATING_SAVE PublicFloatSave
)
{
    SwapTibs();

    DebugPrint("KeRestoreFloatingPointSave: 0x%08x", PublicFloatSave);

    // TODO

    SwapTibs();
    return STATUS_UNSUCCESSFUL;

}

NTSTATUS WINAPI Dirtbox::KeSaveFloatingPointState(
    PKFLOATING_SAVE PublicFloatSave
)
{
    SwapTibs();

    DebugPrint("KeRestoreFloatingPointSave: 0x%08x", PublicFloatSave);

    // TODO

    SwapTibs();
    return STATUS_UNSUCCESSFUL;
}

LONG WINAPI Dirtbox::KeSetBasePriorityThread(
    PKTHREAD Thread, LONG Increment
)
{
    SwapTibs();

    DebugPrint("KeSetBasePriorityThread: 0x%08x %i", Thread, Increment);

    // To set the "real" value, use NtSetInformationThread

    // TODO
    KPRIORITY Res = Thread->BasePriority - 8; // 8 == System process's base priority
    if (Thread->Saturation)
        Res = Thread->Saturation * 16;

    SwapTibs();
    return Res;
}

BOOLEAN WINAPI Dirtbox::KeSetDisableBoostThread(
    PKTHREAD Thread, BOOLEAN Disable
)
{
    SwapTibs();

    DebugPrint("KeSetDisableBoostThread: 0x%08x", Thread, Disable);

    BOOLEAN Res = Thread->DisableBoost;
    Thread->DisableBoost = Disable;

    SwapTibs();
    return Res;
}

BOOLEAN WINAPI Dirtbox::KeSetEvent(
    PKEVENT Event, LONG Increment, BOOLEAN Wait
)
{
    SwapTibs();

    DebugPrint("KeSetEvent: 0x%08x %i %i", Event, Increment, Wait);

    if (Event->Header.Type != 0)
        FatalPrint("KeSetEvent: Events other than Notification Events not implemented.");

    if (Event->Header.WaitListHead.Flink != &Event->Header.WaitListHead)
        FatalPrint("KeSetEvent: Events with more than two threads not supported.");

    // Event->Header.SignalState = 1;
    BOOLEAN Res = SetEvent(GetDirtObject(Event));

    SwapTibs();
    return Res;
}

BOOLEAN WINAPI Dirtbox::KeSetTimer(
    PKTIMER Timer, LARGE_INTEGER DueTime, PKDPC Dpc
)
{
    return KeSetTimerEx(Timer, DueTime, 0, Dpc);
}

BOOLEAN WINAPI Dirtbox::KeSetTimerEx(
    PKTIMER Timer, LARGE_INTEGER DueTime, LONG Period, PKDPC Dpc
)
{
    SwapTibs();

    DebugPrint("KeSetTimerEx: 0x%08x 0x%08x %i 0x%08x", Timer, DueTime, Period, Dpc);

    // TODO: Handle APCs/DPCs
    BOOLEAN Res = SetWaitableTimer(GetDirtObject(Timer), &DueTime, Period, NULL, NULL, FALSE);

    SwapTibs();
    return Res;
}

VOID WINAPI Dirtbox::KeStallExecutionProcessor(
    DWORD MicroSeconds
)
{
    SwapTibs();

    DebugPrint("KeStallExecutionProcessor: %i", MicroSeconds);
    
    LARGE_INTEGER Interval;
    Interval.QuadPart = MicroSeconds * -10;
    ::NtDelayExecution(FALSE, &Interval);

    SwapTibs();
}

BOOLEAN WINAPI Dirtbox::KeSynchronizeExecution(
    PKINTERRUPT Interrupt, PKSYNCHRONIZE_ROUTINE SynchronizeRoutine, PVOID SynchronizeContext
)
{
    SwapTibs();

    DebugPrint("KeSynchronizeExecution: 0x%08x 0x%08x 0x%08x", 
        Interrupt, SynchronizeRoutine, SynchronizeContext);

    // I don't think we need to do anything here for now

    SwapTibs();
    return TRUE;
}

NTSTATUS WINAPI Dirtbox::KeWaitForMultipleObjects(
    DWORD Count, PVOID *Object, WAIT_TYPE WaitType, KWAIT_REASON WaitReason, 
    KPROCESSOR_MODE WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout, 
    PKWAIT_BLOCK WaitBlockArray
)
{
    SwapTibs();

    DebugPrint("KeWaitForMultipleObjects: 0x%x 0x%08x %i %i %i %i 0x%08x 0x%08x", 
        Count, Object, WaitType, WaitReason, WaitMode, Alertable, Timeout, WaitBlockArray);

    PHANDLE Handles = (PHANDLE)malloc(Count * sizeof(HANDLE));
    for (DWORD i = 0; i < Count; i++)
        Handles[i] = GetDirtObject(Object[i]);
    DWORD Milliseconds = (DWORD)(Timeout->QuadPart / -10000);
    NTSTATUS Res = (NTSTATUS)WaitForMultipleObjectsEx(
        Count, Handles, WaitType == WaitAll, Milliseconds, Alertable
    );

    free(Handles);

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::KeWaitForSingleObject(
    PVOID Object, KWAIT_REASON WaitReason, KPROCESSOR_MODE WaitMode, BOOLEAN Alertable, 
    PLARGE_INTEGER Timeout
)
{
    SwapTibs();

    DebugPrint("KeWaitForSingleObject: 0x%08x %i %i %i 0x%08x", 
        Object, WaitReason, WaitMode, Alertable, Timeout);

    // TODO: We gotta signal the VBlank object

    DWORD Milliseconds = (DWORD)(Timeout->QuadPart / -10000);
    NTSTATUS Res = (NTSTATUS)WaitForSingleObjectEx(
        GetDirtObject(Object), Milliseconds, Alertable
    );

    SwapTibs();
    return STATUS_SUCCESS;
}

DWORD __fastcall Dirtbox::KfRaiseIrql(KIRQL NewIrql)
{
    PKPCR Kpcr = (PKPCR)__readfsdword(KPCR_SELF_PCR);
    SwapTibs();

    DebugPrint("KfRaiseIrql: %i", NewIrql);

    Kpcr->Irql = NewIrql;

    SwapTibs();
    return 0;
}

DWORD __fastcall Dirtbox::KfLowerIrql(KIRQL NewIrql)
{
    PKPCR Kpcr = (PKPCR)__readfsdword(KPCR_SELF_PCR);
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

    DebugPrint("MmClaimGpuInstanceMemory: 0x%x 0x%08x", NumberOfBytes, NumberOfPaddingBytes);

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

    DebugPrint("MmFreeContiguousMemory: 0x%08x", BaseAddress);

    VirtualFree(BaseAddress, 0, MEM_RELEASE);

    SwapTibs();
}

DWORD WINAPI Dirtbox::MmGetPhysicalAddress(
    PVOID BaseAddress
)
{
    SwapTibs();

    DebugPrint("MmGetPhysicalAddress: 0x%08x", BaseAddress);

    SwapTibs();
    return (DWORD)BaseAddress;
}

VOID WINAPI Dirtbox::MmLockUnlockBufferPages(
    PVOID BaseAddress, DWORD NumberOfBytes, BOOLEAN UnlockPages
)
{
    SwapTibs();

    DebugPrint("MmLockUnlockBufferPages: 0x%08x 0x%x %i", 
        BaseAddress, NumberOfBytes, UnlockPages);

    SwapTibs();
}

VOID WINAPI Dirtbox::MmLockUnlockPhysicalPage(
    DWORD PhysicalAddress, BOOLEAN UnlockPage
)
{
    SwapTibs();

    DebugPrint("MmLockUnlockBufferPages: 0x%08x %i", PhysicalAddress, UnlockPage);

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

    DebugPrint("MmQueryAddressProtect: 0x%08x", VirtualAddress);

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

    DebugPrint("MmQueryAllocationSize: 0x%08x", BaseAddress);

    MEMORY_BASIC_INFORMATION MemInfo;
    VirtualQuery(BaseAddress, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION));

    SwapTibs();
    return MemInfo.RegionSize;
}

NTSTATUS WINAPI Dirtbox::MmQueryStatistics(
    PMM_STATISTICS MemoryStatistics
)
{
    SwapTibs();

    DebugPrint("MmQueryStatistics: 0x%08x", MemoryStatistics);

    SwapTibs();
    return STATUS_UNSUCCESSFUL;
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

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtClose(
    HANDLE Handle
)
{
    SwapTibs();

    DebugPrint("NtClose: 0x%x", Handle);

    NTSTATUS Res = ::NtClose(Handle);

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtCreateEvent(
    PHANDLE EventHandle, PXBOX_OBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, 
    BOOLEAN InitialState
)
{
    SwapTibs();

    DebugPrint("NtCreateEvent: 0x%08x 0x%08x \"%s\" 0x%x %i", 
        EventHandle, ObjectAttributes, ObjectAttributes->ObjectName->Buffer, EventType,
        InitialState);

    ACCESS_MASK NtDesiredAccess = EVENT_ALL_ACCESS;
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
    Res = ::NtCreateEvent(
        EventHandle, NtDesiredAccess, &NtObjectAttributes, EventType, InitialState
    );

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtCreateFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess, PXBOX_OBJECT_ATTRIBUTES ObjectAttributes, 
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

NTSTATUS WINAPI Dirtbox::NtCreateSemaphore(
    PHANDLE SemaphoreHandle, PXBOX_OBJECT_ATTRIBUTES ObjectAttributes, 
    LONG InitialCount, LONG MaximumCount
)
{
    SwapTibs();

    DebugPrint("NtCreateSemaphore: 0x%08x 0x%08x \"%s\" %i %i", 
        SemaphoreHandle, ObjectAttributes, ObjectAttributes->ObjectName->Buffer,
        InitialCount, MaximumCount);

    ACCESS_MASK NtDesiredAccess = SEMAPHORE_ALL_ACCESS;
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
    Res = ::NtCreateSemaphore(
        SemaphoreHandle, NtDesiredAccess, &NtObjectAttributes, InitialCount, MaximumCount
    );

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtDeviceIoControlFile(
    HANDLE FileHandle, PKEVENT Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, 
    PIO_STATUS_BLOCK IoStatusBlock, DWORD IoControlCode, 
    PVOID InputBuffer, DWORD InputBufferLength, PVOID OutputBuffer, DWORD OutputBufferLength
)
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

    DebugPrint("NtFlushBuffersFile: 0x%08x 0x%08x", FileHandle, IoStatusBlock);

    NTSTATUS Res = ::NtFlushBuffersFile(FileHandle, IoStatusBlock);

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
    HANDLE FileHandle, PKEVENT Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, 
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
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS WINAPI Dirtbox::NtPulseEvent(
    PHANDLE EventHandle, PLONG PreviousState
)
{
    SwapTibs();

    DebugPrint("NtPulseEvent: 0x%08x 0x%08x", EventHandle, PreviousState);

    NTSTATUS Res = ::NtPulseEvent(EventHandle, PreviousState);

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtQueryDirectoryFile(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, 
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, DWORD Length, 
    FILE_INFORMATION_CLASS FileInformationClass, PANSI_STRING FileName, BOOLEAN RestartScan
)
{
    SwapTibs();

    DebugPrint("NtQueryDirectoryFile: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%x " 
        "0x%08x \"%s\" %i", 
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, 
        FileInformationClass, FileName->Buffer, RestartScan);

    UNICODE_STRING NtFileName;
    WCHAR Buffer[MAX_PATH];
    RtlInitEmptyUnicodeString(&NtFileName, Buffer, MAX_PATH);
    RtlAnsiStringToUnicodeString(&NtFileName, FileName, FALSE);

    // not sure if ReturnSingleEntry should be FALSE
    NTSTATUS Res = ::NtQueryDirectoryFile(
        FileHandle, Event, NULL, NULL, IoStatusBlock, FileInformation, Length, 
        FileInformationClass, FALSE, &NtFileName, RestartScan
    );

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtQueryInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, DWORD Length, 
    FILE_INFORMATION_CLASS FileInformationClass
)
{
    SwapTibs();

    DebugPrint("NtQueryInformationFile: 0x%08x 0x%08x 0x%08x 0x%x 0x%x", 
        FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);

    NTSTATUS Res = ::NtQueryInformationFile(
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
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS WINAPI Dirtbox::NtQueryVirtualMemory(
    PVOID BaseAddress, PMEMORY_BASIC_INFORMATION MemoryInformation
)
{
    SwapTibs();

    DebugPrint("NtQueryVirtualMemory: 0x%08x 0x%08x", BaseAddress, MemoryInformation);

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

    NTSTATUS Res = ::NtQueryVolumeInformationFile(
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
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, DWORD Length, PLARGE_INTEGER ByteOffset
)
{
    SwapTibs();

    DebugPrint("NtReadFile: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%x 0x%08x", 
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset);

    NTSTATUS Res = ::NtReadFile(
        FileHandle, Event, NULL, NULL, IoStatusBlock, Buffer, Length, ByteOffset, NULL
    );

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtReleaseSemaphore(
    HANDLE SemaphoreHandle, LONG ReleaseCount, PLONG PreviousCount
)
{
    SwapTibs();

    DebugPrint("NtReleaseSemaphore: 0x%08x %i 0x%08x", 
        SemaphoreHandle, ReleaseCount, PreviousCount);

    NTSTATUS Res = ::NtReleaseSemaphore(SemaphoreHandle, ReleaseCount, PreviousCount);

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtResumeThread(
    HANDLE ThreadHandle, PDWORD PreviousSuspendCount
)
{
    SwapTibs();

    DebugPrint("NtResumeThread: 0x%08x 0x%08x", ThreadHandle, PreviousSuspendCount);

    NTSTATUS Res = ::NtResumeThread(ThreadHandle, PreviousSuspendCount);

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtSetEvent(
    HANDLE EventHandle, PLONG PreviousState
)
{
    SwapTibs();

    DebugPrint("NtSetEvent: 0x%08x 0x%08x", EventHandle, PreviousState);

    NTSTATUS Res = ::NtSetEvent(EventHandle, PreviousState);

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

NTSTATUS WINAPI Dirtbox::NtSuspendThread(
    HANDLE ThreadHandle, PDWORD PreviousSuspendCount
)
{
    SwapTibs();

    DebugPrint("NtSuspendThread: 0x%08x 0x%08x", ThreadHandle, PreviousSuspendCount);

    NTSTATUS Res = ::NtSuspendThread(ThreadHandle, PreviousSuspendCount);

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
    HANDLE Handle, KPROCESSOR_MODE WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Timeout
)
{
    SwapTibs();

    DebugPrint("NtWaitForSingleObjectEx: 0x%08x 0x%x %i 0x%08x", 
        Handle, WaitMode, Alertable, Timeout);

    NTSTATUS Res = ::NtWaitForSingleObject(Handle, Alertable, Timeout);

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtWriteFile( 
    HANDLE FileHandle, PVOID Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, DWORD Length, PLARGE_INTEGER ByteOffset
)
{
    SwapTibs();

    DebugPrint("NtWriteFile: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%x 0x%08x", 
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset);

    NTSTATUS Res = ::NtWriteFile(
        FileHandle, Event, NULL, NULL, IoStatusBlock, Buffer, Length, ByteOffset, NULL
    );

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtYieldExecution()
{
    SwapTibs();

    DebugPrint("NtYieldExecution");

    NTSTATUS Res = ::NtYieldExecution();

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::ObReferenceObjectByHandle(
    HANDLE Handle, POBJECT_TYPE ObjectType, PVOID *ReturnedObject
)
{
    SwapTibs();

    DebugPrint("ObReferenceObjectByHandle: 0x%08x 0x%08x 0x%08x", 
        Handle, ObjectType, ReturnedObject);

    if (ObjectType == &PsThreadObjectType)
    {
        // TODO
        *ReturnedObject = NULL;
        SwapTibs();
        return STATUS_UNSUCCESSFUL;
    }
    else
    {
        OBJECT_NAME_INFORMATION Info;
        NTSTATUS Res = ::NtQueryObject(
            Handle, ObjectNameInformation, &Info, sizeof(OBJECT_NAME_INFORMATION), NULL
        );
        if (!NT_SUCCESS(Res))
            *ReturnedObject = NULL;
        else
            *ReturnedObject = (PVOID)_wtol(Info.Name.Buffer + 8);
        // 8 == length of "Dirtbox_"
        SwapTibs();
        return Res;
    }
}

VOID __fastcall Dirtbox::ObfDereferenceObject(
    PVOID Object
)
{
    SwapTibs();

    DebugPrint("ObfDereferenceObject: 0x%08x", Object);

    SwapTibs();
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

    // Try to lock it
    if (InterlockedIncrement(&CriticalSection->LockCount) != 0)
    {
        // We've failed to lock it! Does this thread
        // actually own it?
        if (CriticalSection->OwningThread == Kpcr->Prcb->CurrentThread)
        {
            // You own it, so you'll get it when you're done with it! No need to
            // use the interlocked functions as only the thread who already owns
            // the lock can modify this data.
            CriticalSection->RecursionCount++;
            SwapTibs();
            return STATUS_SUCCESS;
        }

        // NOTE - CriticalSection->OwningThread can be NULL here because changing
        //        this information is not serialized. This happens when thread a
        //        acquires the lock (LockCount == 0) and thread b tries to
        //        acquire it as well (LockCount == 1) but thread a hasn't had a
        //        chance to set the OwningThread! So it's not an error when
        //        OwningThread is NULL here!

        // We don't own it, so we must wait for it
        ::NtWaitForSingleObject(GetDirtObject(CriticalSection), TRUE, NULL);
    }

    // Lock successful. Changing this information has not to be serialized because
    // only one thread at a time can actually change it (the one who acquired
    // the lock)!
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

NTSTATUS WINAPI Dirtbox::RtlLeaveCriticalSection(
    PXBOX_CRITICAL_SECTION CriticalSection
)
{
    SwapTibs();

    DebugPrint("RtlLeaveCriticalSection: 0x%08x", CriticalSection);

    // Decrease the Recursion Count. No need to do this atomically because only
    // the thread who holds the lock can call this function (unless the program
    // is totally screwed...
    CriticalSection->RecursionCount--;
    if (CriticalSection->RecursionCount)
    {
        // Someone still owns us, but we are free. This needs to be done atomically.
        InterlockedDecrement(&CriticalSection->LockCount);
    }
    else
    {
         // Nobody owns us anymore. No need to do this atomically.
        CriticalSection->OwningThread = 0;

        // Was someone wanting us? This needs to be done atomically.
        if (InterlockedDecrement(&CriticalSection->LockCount) != -1)
            ::NtSetEvent(GetDirtObject(CriticalSection), NULL);
    }

    SwapTibs();
    return STATUS_SUCCESS;
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

BOOLEAN WINAPI Dirtbox::RtlTimeFieldsToTime(
    PTIME_FIELDS TimeFields, PLARGE_INTEGER Time
)
{
    SwapTibs();

    DebugPrint("RtlTimeFieldsToTime: 0x%08x 0x%08x", TimeFields, Time);

    BOOLEAN Res = ::RtlTimeFieldsToTime(TimeFields, Time);

    SwapTibs();
    return Res;
}

VOID WINAPI Dirtbox::RtlTimeToTimeFields(
    PLARGE_INTEGER Time, PTIME_FIELDS TimeFields
)
{
    SwapTibs();


    DebugPrint("RtlTimeToTimeFields: 0x%08x 0x%08x", Time, TimeFields);

    ::RtlTimeToTimeFields(Time, TimeFields);

    SwapTibs();
}

BOOLEAN WINAPI Dirtbox::RtlTryEnterCriticalSection(
    PXBOX_CRITICAL_SECTION CriticalSection
)
{
    PKPCR Kpcr = (PKPCR)__readfsdword(KPCR_SELF_PCR);

    SwapTibs();

    DebugPrint("RtlTryEnterCriticalSection: 0x%08x", CriticalSection);

    BOOLEAN Res;
    /* Try to take control */
    if (InterlockedCompareExchange(&CriticalSection->LockCount, 0, -1) == -1)
    {
        /* It's ours */
        CriticalSection->OwningThread = Kpcr->Prcb->CurrentThread;
        CriticalSection->RecursionCount = 1;
        return TRUE;

    }
    else if (CriticalSection->OwningThread == Kpcr->Prcb->CurrentThread)
    {
        /* It's already ours */
        InterlockedIncrement(&CriticalSection->LockCount);
        CriticalSection->RecursionCount++;
        return TRUE;
    }
    else
    {
        /* It's not ours */
        Res = FALSE;
    }

    SwapTibs();
    return Res;
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

VOID WINAPI Dirtbox::HalInitiateShutdown()
{
    SwapTibs();

    DebugPrint("HalInitiateShutdown");

    SwapTibs();
}
