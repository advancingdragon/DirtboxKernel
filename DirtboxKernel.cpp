#include "Dirtbox.h"
#include "Native.h"

using namespace Dirtbox;

DWORD Dirtbox::HalDiskCachePartitionCount = 3;
XBOX_HARDWARE_INFO Dirtbox::XboxHardwareInfo;
DWORD Dirtbox::LaunchDataPage;
DWORD Dirtbox::XboxHDKey;
DWORD Dirtbox::XboxKrnlVersion;
DWORD Dirtbox::XeImageFileName;
DWORD Dirtbox::IdexChannelObject;

// TODO: need to put critical sections around each of these
// in case they are used in a multithreaded way
static PVOID AvpSavedDataAddress = (PVOID)0;

#define IN_DRIVE(path, drive) \
    (toupper((path)[0]) == drive && path[1] == ':' && path[2] == '\\')

PVOID WINAPI Dirtbox::AvGetSavedDataAddress()
{
    SwapTibs();

    DEBUG_PRINT("AvGetSavedDataAddress\n");

    SwapTibs();
    return AvpSavedDataAddress;
}

VOID WINAPI Dirtbox::AvSendTVEncoderOption(
    PVOID RegisterBase, DWORD Option, DWORD Param, PDWORD Result
)
{
    SwapTibs();

    DEBUG_PRINT("AvSendTVEncoderOption: 0x%08x %i %i\n", 
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
    DEBUG_PRINT("AvSetDisplayMode: 0x%08x %i %i %i %i 0x%x\n", 
        RegisterBase, Step, Mode, Format, Pitch, FrameBuffer);

    SwapTibs();
    return 0;
}

VOID WINAPI Dirtbox::AvSetSavedDataAddress(
    PVOID Address
)
{
    SwapTibs();

    DEBUG_PRINT("AvSetSavedDataAddress: 0x%08x\n", 
        Address);

    AvpSavedDataAddress = Address;

    SwapTibs();
}

NTSTATUS WINAPI Dirtbox::DbgPrint(
    PSTR Output
)
{
    SwapTibs();

    DEBUG_PRINT("DbgPrint: \"%s\"\n", Output);

    SwapTibs();
    return STATUS_SUCCESS;
}

// export 24
NTSTATUS WINAPI Dirtbox::ExQueryNonVolatileSetting(
    DWORD ValueIndex, DWORD *Type, PBYTE Value, SIZE_T ValueLength,
    PSIZE_T ResultLength
)
{
    SwapTibs();

    DEBUG_PRINT("ExQueryNonVolatileSetting: %i ...\n", ValueIndex);

    SwapTibs();

    switch(ValueIndex)
    {
    case 7: // Language
        *(DWORD *)Value = 1;
        return STATUS_SUCCESS;
    case 10: // Parental control setting
        *(DWORD *)Value = 0;
        return STATUS_SUCCESS;
    default:
        return -1;
    }
}

DWORD WINAPI Dirtbox::HalGetInterruptVector(
    DWORD BusInterruptLevel, PKIRQL Irql
)
{
    SwapTibs();

    DEBUG_PRINT("HalGetInterruptVector: 0x%x 0x%08x\n", 
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

    DEBUG_PRINT("HalReadWritePCISpace: 0x%x 0x%x 0x%x 0x%08x %i %i\n", 
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

    DEBUG_PRINT("HalRegisterShutdownNotification: 0x%08x 0x%x\n", 
        ShutdownRegistration, Register);

    SwapTibs();
}

VOID WINAPI Dirtbox::HalReturnToFirmware(
    RETURN_FIRMWARE Routine
)
{
    SwapTibs();

    DEBUG_PRINT("HalReturnToFirmware: 0x%x\n", 
        Routine);

    ExitProcess(0);
}

NTSTATUS WINAPI Dirtbox::IoCreateSymbolicLink(
    PANSI_STRING SymbolicLinkName,
    PANSI_STRING DeviceName
)
{
    SwapTibs();

    DEBUG_PRINT("IoCreateSymbolicLink: \"%s\" \"%s\"\n", 
        SymbolicLinkName->Buffer, DeviceName->Buffer);

    // TODO: critical section

    SwapTibs();
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI Dirtbox::IoDeleteSymbolicLink(
    PANSI_STRING SymbolicLinkName
)
{
    SwapTibs();

    DEBUG_PRINT("IoDeleteSymbolicLink: \"%s\"\n", 
        SymbolicLinkName->Buffer);

    // TODO: critical section

    SwapTibs();
    return STATUS_SUCCESS;
}

VOID WINAPI Dirtbox::KeBugCheck(
    DWORD BugCheckCode
)
{
    SwapTibs();

    DEBUG_PRINT("KeBugCheck: %i\n", 
        BugCheckCode);

    ExitProcess(1);
}

BOOLEAN WINAPI Dirtbox::KeConnectInterrupt(
    PKINTERRUPT Interrupt
)
{
    SwapTibs();

    DEBUG_PRINT("KeConnectInterrupt: %i %i %i %i %i %i\n",
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

    DEBUG_PRINT("KeDelayExecutionThread: %i %i 0x%08x\n", 
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
    DEBUG_PRINT("KeDisconnectInterrupt: 0x%08x 0x%08x %i %i %i %i %i %i\n",
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

    DEBUG_PRINT("KeInitializeDpc: 0x%08x 0x%08x 0x%08x\n",
        Dpc, DeferredRoutine, DeferredContext);

    Dpc->DeferredRoutine = DeferredRoutine;
    Dpc->Type = 19;
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

    DEBUG_PRINT("KeInitializeInterrupt: 0x%08x 0x%08x %i %i %i %i\n",
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

    DEBUG_PRINT("KeInitializeTimerEx: %i %i 0x%08x\n", 
        Timer, Type);

    Timer->Header.Type = Type + 8;
    Timer->Header.Inserted = 0;
    Timer->Header.Size = 10;
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

    DEBUG_PRINT("KeInsertQueueDpc: %i %i 0x%08x 0x%08x\n",
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

    DEBUG_PRINT("KeQuerySystemTime: 0x%08x\n",
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

    DEBUG_PRINT("KeRaiseIrqlToDpcLevel\n");

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

    DEBUG_PRINT("KeSetEvent: 0x%08x %i %i\n",
        Event, Increment, Wait);

    // thinking of how to implement Ke events with the Windows API event objects.
    // maybe a hash table of addresses of KEVENT objects?
    if (Event->Header.Type != 0)
    {
        DEBUG_PRINT("KeSetEvent: Events other than Notification Events not implemented.\n");
        ExitProcess(1);
    }

    if (Event->Header.WaitListHead.Flink != &Event->Header.WaitListHead)
    {
        DEBUG_PRINT("KeSetEvent: Events with more than two threads not supported.\n");
        ExitProcess(1);
    }

    Event->Header.SignalState = 1;

    SwapTibs();
    return TRUE;
}

BOOLEAN WINAPI Dirtbox::KeSetTimer(
    PKTIMER Timer, LARGE_INTEGER DueTime, PKDPC Dpc
)
{
    SwapTibs();

    DEBUG_PRINT("KeSetTimer: 0x%08x 0x%08x 0x%08x\n",
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

    DEBUG_PRINT("KeWaitForSingleObject: 0x%08x %i %i %i %i 0x%08x\n",
        Object, WaitReason, WaitMode, Alertable, Timeout);

    while (((PKEVENT)Object)->Header.SignalState > 0)
    {
    }

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

    DEBUG_PRINT("KfLowerIrql: %i\n", NewIrql);

    Kpcr->Irql = NewIrql;

    SwapTibs();
    return 0;
}

PVOID WINAPI Dirtbox::MmAllocateContiguousMemory(
    DWORD NumberOfBytes
)
{
    return MmAllocateContiguousMemoryEx(NumberOfBytes, 0, 0xFFFFFFFFu, 0, PAGE_READWRITE);
}

PVOID WINAPI Dirtbox::MmAllocateContiguousMemoryEx(
    DWORD NumberOfBytes, DWORD LowestAcceptableAddress, DWORD HighestAcceptableAddress,
    DWORD Alignment, DWORD ProtectionType
)
{
    SwapTibs();

    DEBUG_PRINT("MmAllocateContiguousMemoryEx: 0x%x 0x%08x 0x%08x 0x%x 0x%08x\n",
        NumberOfBytes, LowestAcceptableAddress, HighestAcceptableAddress, Alignment, ProtectionType);

    PVOID Buf;
    DWORD AlignmentMask = ~(Alignment - 1);
    DWORD StartAddress;
    DWORD EndAddress;
    if (HighestAcceptableAddress == 0xFFFFFFFF)
        EndAddress = 0x83FD6000;
    else
        EndAddress = HighestAcceptableAddress | 0x80000000;

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

    DEBUG_PRINT("MmClaimGpuInstanceMemory: 0x%x 0x%08x\n",
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

    DEBUG_PRINT("MmFreeContiguousMemory: 0x%08x\n",
        BaseAddress);

    VirtualFree(BaseAddress, 0, MEM_RELEASE);

    SwapTibs();
}

VOID WINAPI Dirtbox::MmPersistContiguousMemory(
    PVOID BaseAddress, DWORD NumberOfBytes, BOOLEAN Persist
)
{
    SwapTibs();

    DEBUG_PRINT("MmPersistContiguousMemory: 0x%08x 0x%x %i\n",
        BaseAddress, NumberOfBytes, Persist);

    // Not sure if we need to implement this

    SwapTibs();
}

DWORD WINAPI Dirtbox::MmQueryAddressProtect(
    PVOID VirtualAddress
)
{
    SwapTibs();

    DEBUG_PRINT("MmQueryAddressProtect: 0x%08x\n",
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

    DEBUG_PRINT("MmQueryAllocationSize: 0x%08x\n",
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

    DEBUG_PRINT("MmSetAddressProtect: 0x%08x 0x%x 0x%08x\n",
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

    DEBUG_PRINT("NtAllocateVirtualMemory: 0x%08x 0x%x 0x%x 0x%x 0x%x\n",
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

    DEBUG_PRINT("NtClose: 0x%x",
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
    NTSTATUS Res;

    SwapTibs();

    DEBUG_PRINT("NtCreateFile: 0x%08x 0x%x 0x%08x \"%s\" 0x%08x 0x%08x 0x%x 0x%x 0x%x 0x%x\n",
        FileHandle, DesiredAccess, ObjectAttributes, ObjectAttributes->ObjectName->Buffer, 
        IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, 
        CreateDisposition, CreateOptions);

    if (ObjectAttributes->RootDirectory == OB_DOS_DEVICES)
    {
        // Patch drives to directories
        CHAR Buffer[MAX_PATH];
        switch (toupper(ObjectAttributes->ObjectName->Buffer[0]))
        {
        case 'D':
            strncpy_s(Buffer, MAX_PATH, "\\??\\C:\\Dirtbox\\D\\", MAX_PATH);
            break;
        case 'T':
            strncpy_s(Buffer, MAX_PATH, "\\??\\C:\\Dirtbox\\T\\", MAX_PATH);
            break;
        case 'U':
            strncpy_s(Buffer, MAX_PATH, "\\??\\C:\\Dirtbox\\U\\", MAX_PATH);
            break;
        case 'Z':
            strncpy_s(Buffer, MAX_PATH, "\\??\\C:\\Dirtbox\\Z\\", MAX_PATH);
            break;
        default:
            DEBUG_PRINT("NtCreateFile: invalid drive.\n");
            ExitProcess(1);
            break;
        }
        strncat_s(Buffer, MAX_PATH, &ObjectAttributes->ObjectName->Buffer[3], MAX_PATH);

        // Convert Xbox path (in ANSI) to Windows NT format (UNICODE_STRING)
        WCHAR UnicodeBuffer[MAX_PATH];
        UNICODE_STRING ObjectName;
        size_t Converted;
        mbstowcs_s(&Converted, UnicodeBuffer, MAX_PATH, Buffer, MAX_PATH);
        ObjectName.Length = wcslen(UnicodeBuffer) * sizeof(WCHAR);
        ObjectName.MaximumLength = MAX_PATH;
        ObjectName.Buffer = UnicodeBuffer;

        // Convert XBOX_OBJECT_ATTRIBUTES to Windows NT OBJECT_ATTRIBUTES
        OBJECT_ATTRIBUTES NtObjectAttributes;
        NtObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
        NtObjectAttributes.ObjectName = &ObjectName;
        NtObjectAttributes.Attributes = ObjectAttributes->Attributes;
        NtObjectAttributes.RootDirectory = NULL;
        NtObjectAttributes.SecurityDescriptor = NULL;

        // Call Windows NT equivalent
        Res = ::NtCreateFile(
            FileHandle, DesiredAccess, &NtObjectAttributes, IoStatusBlock, 
            AllocationSize, FileAttributes, ShareAccess, CreateDisposition, 
            CreateOptions, NULL, 0
        );
    }
    else if (ObjectAttributes->RootDirectory == NULL)
    {
        if (CreateOptions & 1)
            Res = STATUS_NOT_A_DIRECTORY;
        else
            Res = STATUS_OBJECT_NAME_COLLISION;
    }
    else
    {
        DEBUG_PRINT("NtCreateFile: Invalid root directory.\n");
        ExitProcess(1);
    }

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtDeviceIoControlFile(
    HANDLE FileHandle, PKEVENT Event, PVOID ApcRoutine, PVOID ApcContext, 
    PIO_STATUS_BLOCK IoStatusBlock, DWORD IoControlCode, PVOID InputBuffer, DWORD InputBufferLength, 
    PVOID OutputBuffer, DWORD OutputBufferLength)
{
    SwapTibs();

    DEBUG_PRINT("NtDeviceIoControlFile: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%x " 
        "0x%08x 0x%x 0x%08x 0x%x\n",
        FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength,
        OutputBuffer, OutputBufferLength);

    // TODO: not needed unless mounting utility drive

    SwapTibs();
    return -1;
}

NTSTATUS WINAPI Dirtbox::NtFlushBuffersFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock
)
{
    SwapTibs();

    DEBUG_PRINT("NtFlushBuffersFile: 0x%08x 0x%08x\n", 
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

    DEBUG_PRINT("NtFreeVirtualMemory: 0x%08x 0x%08x 0x%x\n", 
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

    DEBUG_PRINT("NtFsControlFile: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%x " 
        "0x%08x 0x%x 0x%08x 0x%x\n",
        FileHandle, Event, ApcRoutine, ApcContext,
        IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength,
        OutputBuffer, OutputBufferLength);

    // TODO: not needed unless mounting utility drive

    SwapTibs();
    return -1;
}

NTSTATUS WINAPI Dirtbox::NtOpenFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess, PXBOX_OBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, DWORD ShareAccess, DWORD OpenOptions
)
{
    SwapTibs();

    DEBUG_PRINT("NtOpenFile: 0x%08x 0x%x 0x%08x \"%s\" 0x%08x 0x%x 0x%x\n",
        FileHandle, DesiredAccess, ObjectAttributes, ObjectAttributes->ObjectName->Buffer, 
        IoStatusBlock, ShareAccess, OpenOptions);

    // TODO: not needed unless mounting utility drive or setting up drive

    SwapTibs();
    return -1;
}

NTSTATUS WINAPI Dirtbox::NtOpenSymbolicLinkObject(
    PHANDLE LinkHandle, PXBOX_OBJECT_ATTRIBUTES ObjectAttributes
)
{
    SwapTibs();

    DEBUG_PRINT("NtOpenSymbolicLinkObject: 0x%08x 0x%08x \"%s\"",
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

    DEBUG_PRINT("NtQueryInformationFile: 0x%08x 0x%08x 0x%08x 0x%x 0x%x\n",
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

    DEBUG_PRINT("NtOpenSymbolicLinkObject: 0x%08x 0x%08x 0x%x",
        LinkHandle, LinkTarget, ReturnedLength);

    // Can fail, then it assumes to be CD-ROM

    SwapTibs();
    return -1;
}

NTSTATUS WINAPI Dirtbox::NtQueryVirtualMemory(
    PVOID BaseAddress, PMEMORY_BASIC_INFORMATION MemoryInformation
)
{
    SwapTibs();

    DEBUG_PRINT("NtQueryVirtualMemory: 0x%08x 0x%08x\n",
        BaseAddress, MemoryInformation);

    NTSTATUS Res = VirtualQuery(
        BaseAddress, MemoryInformation, sizeof(MEMORY_BASIC_INFORMATION)
    );

    SwapTibs();
    return Res;
}

NTSTATUS WINAPI Dirtbox::NtQueryVolumeInformationFile(
    HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation, DWORD Length, 
    DWORD FsInformationClass
)
{
    SwapTibs();

    DEBUG_PRINT("NtOpenFile: 0x%08x 0x%08x 0x%08x 0x%x 0x%08x\n",
        FileHandle, IoStatusBlock, FsInformation, Length, FsInformationClass);

    // TODO: not needed unless mounting utility drive or setting up drive

    SwapTibs();
    return -1;
}

NTSTATUS WINAPI Dirtbox::NtReadFile(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, DWORD Length, PLARGE_INTEGER ByteOffset
)
{
    SwapTibs();

    DEBUG_PRINT("NtReadFile: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%x 0x%08x\n",
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

    DEBUG_PRINT("NtSetInformationFile: 0x%08x 0x%08x 0x%08x 0x%x 0x%x\n",
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

    DEBUG_PRINT("NtWaitForSingleObjectEx: 0x%08x 0x%x %i 0x%08x\n",
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

    DEBUG_PRINT("NtWriteFile: 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%x 0x%08x\n",
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

    DEBUG_PRINT("PsCreateSystemThreadEx: 0x%08x 0x%x 0x%x 0x%x 0x%08x "
        "0x%08x 0x%08x %i %i 0x%08x\n",
        ThreadHandle, ThreadExtensionSize, KernelStackSize, TlsDataSize, ThreadId, 
        StartRoutine, StartContext, CreateSuspended, DebuggerThread, SystemRoutine);

    PSHIM_CONTEXT ShimContext = (PSHIM_CONTEXT)malloc(sizeof(PSHIM_CONTEXT));
    if (ShimContext == NULL)
    {
        DEBUG_PRINT("PsCreateSystemThreadEx: failed to allocate shim context.\n");
        SwapTibs();
        return -1;
    }

    ShimContext->TlsDataSize = TlsDataSize;
    ShimContext->StartRoutine = StartRoutine;
    ShimContext->StartContext = StartContext;
    ShimContext->SystemRoutine = SystemRoutine;

    DWORD Flags = CreateSuspended ? CREATE_SUSPENDED : 0;

    *ThreadHandle = CreateThread(
        NULL, KernelStackSize, ShimCallback, ShimContext, Flags, ThreadId
    );
    if (*ThreadHandle == NULL)
    {
        free(ShimContext);
        SwapTibs();
        return -1;
    }

    SwapTibs();
    return STATUS_SUCCESS;
}

VOID WINAPI Dirtbox::PsTerminateSystemThread(
    NTSTATUS ExitStatus
)
{
    SwapTibs();

    // Dont think we have to do anything here, since it's gonna return anyway, for now.
    DEBUG_PRINT("PsTerminateSystemThread: %i\n", ExitStatus);

    SwapTibs();
}

NTSTATUS WINAPI Dirtbox::RtlCompareMemoryUlong(
    PDWORD Buffer, DWORD Size, DWORD Value
)
{
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI Dirtbox::RtlEnterCriticalSection(
    PXBOX_CRITICAL_SECTION CriticalSection
)
{
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI Dirtbox::RtlEqualString(
    PANSI_STRING String1, PANSI_STRING String2, BOOLEAN CaseInSensitive
)
{
    return STATUS_SUCCESS;
}

VOID WINAPI Dirtbox::RtlInitAnsiString(
    PANSI_STRING DestinationString, PSTR SourceString
)
{
}

VOID WINAPI Dirtbox::RtlInitializeCriticalSection(
    PXBOX_CRITICAL_SECTION CriticalSection
)
{
}

VOID WINAPI Dirtbox::RtlLeaveCriticalSection(
    PXBOX_CRITICAL_SECTION CriticalSection
)
{
}

LONG WINAPI Dirtbox::RtlNtStatusToDosError(
    NTSTATUS Status
)
{
    return STATUS_SUCCESS;
}

VOID WINAPI Dirtbox::RtlRaiseException(
    PEXCEPTION_RECORD ExceptionRecord
)
{
}

VOID WINAPI Dirtbox::RtlUnwind(
    PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue
)
{
}

NTSTATUS WINAPI Dirtbox::XeLoadSection(
    PXBEIMAGE_SECTION Section
)
{
    return STATUS_SUCCESS;
}

NTSTATUS WINAPI Dirtbox::XeUnloadSection(
    PXBEIMAGE_SECTION Section
)
{
    return STATUS_SUCCESS;
}

VOID WINAPI Dirtbox::XcSHAInit(
    PCHAR SHAContext
)
{
}

VOID WINAPI Dirtbox::XcSHAUpdate(
    PCHAR SHAContext, PCHAR Input, DWORD InputLength
)
{
}

VOID WINAPI Dirtbox::XcSHAFinal(
    PCHAR SHAContext, PCHAR Digest
)
{
}

VOID WINAPI Dirtbox::XcHMAC(
    PCHAR KeyMaterial, DWORD DwordKeyMaterial, PCHAR Data, DWORD DwordData, 
    PCHAR Data2, DWORD DwordData2, PCHAR Digest
)
{
}

VOID WINAPI Dirtbox::HalInitiateShutdown()
{
}