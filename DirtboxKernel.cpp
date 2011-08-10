#include "Dirtbox.h"

#define _CRT_SECURE_NO_WARNINGS

BOOL WINAPI DllMain(
    HINSTANCE hInstDll, DWORD fdwReason, LPVOID fImpLoad
)
{
    return TRUE;
}

VOID WINAPI Dirtbox::_Initialize()
{
    /*
    MessageBoxA(NULL, "Dongs\n", "Dongs", MB_OK);
    DWORD *KernelImageThunk = (DWORD *)(*(DWORD *)KERNEL_IMAGE_THUNK_ADDR ^ DEBUG_KEY);

    DWORD thunk;
    for (int i = 0; thunk = KernelImageThunk[i] & 0x7FFFFFFF, thunk != NULL; i++)
    {
    }
    return 0;
    */
    Dirtbox::InitializeThreading();
    Dirtbox::AllocateTib();
    AddVectoredExceptionHandler(1, &Dirtbox::ExceptionHandler);
    if (Dirtbox::InitializeGraphics() != 0)
    {
        exit(1);
    }
    // TODO: Call main routine
    SwapTibs();
}

XBOX_HARDWARE_INFO Dirtbox::XboxHardwareInfo;

static LPVOID AvpSavedDataAddress = (LPVOID)0;

LPVOID NTAPI Dirtbox::AvGetSavedDataAddress()
{
    SwapTibs();

    DEBUG_PRINT("AvGetSavedDataAddress\n");

    SwapTibs();
    return AvpSavedDataAddress;
}

VOID NTAPI Dirtbox::AvSendTVEncoderOption(
    LPVOID RegisterBase, DWORD Option, DWORD Param, LPDWORD Result
)
{
    SwapTibs();

    DEBUG_PRINT("AvSendTVEncoderOption: 0x%08x %i %i\n", 
        RegisterBase, Option, Param);

    if (Result != (LPDWORD)0)
        *Result = 0;

    SwapTibs();
}

DWORD NTAPI Dirtbox::AvSetDisplayMode(
    LPVOID RegisterBase, DWORD Step, DWORD Mode, DWORD Format, 
    DWORD Pitch, DWORD FrameBuffer
)
{
    SwapTibs();
    DEBUG_PRINT("AvSetDisplayMode: 0x%08x %i %i %i %i 0x%x\n", 
        RegisterBase, Step, Mode, Format, Pitch, FrameBuffer);

    SwapTibs();
    return 0;
}

VOID NTAPI Dirtbox::AvSetSavedDataAddress(
    LPVOID Address
)
{
    SwapTibs();

    DEBUG_PRINT("AvSetSavedDataAddress: 0x%08x\n", 
        Address);

    AvpSavedDataAddress = Address;

    SwapTibs();
}

NTSTATUS NTAPI Dirtbox::DbgPrint(
    LPSTR Output
)
{
    SwapTibs();

    DEBUG_PRINT("DbgPrint: %s\n", Output);

    SwapTibs();

    return 0;
}

DWORD NTAPI Dirtbox::HalGetInterruptVector(
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

VOID NTAPI Dirtbox::HalReadWritePCISpace(
    DWORD BusNumber, DWORD SlotNumber, DWORD RegisterNumber, LPVOID Buffer, 
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

VOID NTAPI Dirtbox::HalRegisterShutdownNotification(
    PHAL_SHUTDOWN_REGISTRATION ShutdownRegistration, CHAR Register
)
{
    SwapTibs();

    DEBUG_PRINT("HalRegisterShutdownNotification: 0x%08x 0x%x\n", 
        ShutdownRegistration, Register);

    SwapTibs();
}

BOOLEAN NTAPI Dirtbox::KeConnectInterrupt(
    PKINTERRUPT Interrupt
)
{
    SwapTibs();

    DEBUG_PRINT("KeConnectInterrupt: %i %i %i %i %i %i\n",
        Interrupt->BusInterruptLevel, Interrupt->Irql, 
        Interrupt->Connected, Interrupt->ShareVector, 
        Interrupt->Mode, Interrupt->ServiceCount);

    if (!Interrupt->Connected)
    {
        Interrupt->Connected = 1;

        SwapTibs();
        return TRUE;
    }

    SwapTibs();
    return FALSE;
}

BOOLEAN NTAPI Dirtbox::KeDisconnectInterrupt(
    PKINTERRUPT Interrupt
)
{
    SwapTibs();
    DEBUG_PRINT("KeDisconnectInterrupt: 0x%08x 0x%08x %i %i %i %i %i %i\n",
        Interrupt->ServiceRoutine, Interrupt->ServiceContext,
        Interrupt->BusInterruptLevel, Interrupt->Irql, 
        Interrupt->Connected, Interrupt->ShareVector, 
        Interrupt->Mode, Interrupt->ServiceCount);

    if (Interrupt->Connected)
    {
        Interrupt->Connected = 0;

        SwapTibs();
        return TRUE;
    }

    SwapTibs();
    return FALSE;
}

VOID NTAPI Dirtbox::KeInitializeDpc(
    PKDPC Dpc, PKDEFERRED_ROUTINE DeferredRoutine, LPVOID DeferredContext
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

VOID NTAPI Dirtbox::KeInitializeInterrupt(
    PKINTERRUPT Interrupt, PKSERVICE_ROUTINE ServiceRoutine, LPVOID ServiceContext, DWORD Vector,
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

BOOLEAN NTAPI Dirtbox::KeInsertQueueDpc(
    PKDPC Dpc, LPVOID SystemArgument1, LPVOID SystemArgument2
)
{
    SwapTibs();

    DEBUG_PRINT("KeInsertQueueDpc: %i %i 0x%08x 0x%08x\n",
        Dpc->Type, Dpc->Inserted, SystemArgument1, SystemArgument2);

    if (!Dpc->Inserted)
    {
        Dpc->SystemArgument1 = SystemArgument1;
        Dpc->SystemArgument2 = SystemArgument2;
        Dpc->Inserted = 1;

        SwapTibs();
        return TRUE;
    }

    SwapTibs();
    return FALSE;
}

LONG NTAPI Dirtbox::KeSetEvent(
    PKEVENT Event, LONG Increment, CHAR Wait
)
{
    SwapTibs();

    DEBUG_PRINT("KeSetEvent: 0x%08x %i %i\n",
        Event, Increment, Wait);

    SwapTibs();
    return 1;
}

LONG NTAPI Dirtbox::KeWaitForSingleObject(
    LPVOID Object, KWAIT_REASON WaitReason, CHAR WaitMode, CHAR Alertable, 
    PLARGE_INTEGER Timeout
)
{
    SwapTibs();

    DEBUG_PRINT("KeWaitForSingleObject: 0x%08x %i %i %i %i 0x%08x\n",
        Object, WaitReason, WaitMode, Alertable, Timeout);

    SwapTibs();
    return 0;
}

LPVOID NTAPI Dirtbox::MmClaimGpuInstanceMemory(
    DWORD NumberOfBytes, LPDWORD NumberOfPaddingBytes
)
{
    SwapTibs();

    DEBUG_PRINT("MmClaimGpuInstanceMemory: 0x%x 0x%08x\n",
        NumberOfBytes, NumberOfPaddingBytes);

    *NumberOfPaddingBytes = PADDING_SIZE;
    if (NumberOfBytes == 0xFFFFFFFF)
        NumberOfBytes = GPU_INST_SIZE;

    SwapTibs();
    return (LPVOID)(REGISTER_BASE + NV_GPU_INST + PADDING_SIZE + GPU_INST_SIZE);
}

VOID NTAPI Dirtbox::MmFreeContiguousMemory(
    LPVOID BaseAddress
)
{
    SwapTibs();

    DEBUG_PRINT("MmFreeContiguousMemory: 0x%08x\n",
        BaseAddress);

    VirtualFree(BaseAddress, 0, MEM_RELEASE);

    SwapTibs();
}

VOID NTAPI Dirtbox::MmPersistContiguousMemory(
    LPVOID BaseAddress, DWORD NumberOfBytes, BOOLEAN Persist
)
{
    SwapTibs();

    DEBUG_PRINT("MmPersistContiguousMemory: 0x%08x 0x%x %i\n",
        BaseAddress, NumberOfBytes, Persist);

    Dirtbox::MyVirtualAlloc((DWORD)BaseAddress, NumberOfBytes);
    
    SwapTibs();
}

DWORD NTAPI Dirtbox::MmQueryAllocationSize(
    LPVOID BaseAddress
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

NTSTATUS NTAPI Dirtbox::NtClose(
    HANDLE Handle
)
{
    return 0;
}

NTSTATUS NTAPI Dirtbox::NtCreateFile(
    PHANDLE FileHandle, DWORD DesiredAccess, LPVOID ObjectAttributes, LPVOID IoStatusBlock, 
    PLARGE_INTEGER AllocationSize, DWORD FileAttributes, DWORD ShareAccess, 
    DWORD CreateDisposition, DWORD CreateOptions 
)
{
    return 0;
}

NTSTATUS NTAPI Dirtbox::NtReadFile(
    HANDLE FileHandle, HANDLE Event, LPVOID ApcRoutine, LPVOID ApcContext,
    LPVOID IoStatusBlock, LPVOID Buffer, DWORD Length, PLARGE_INTEGER ByteOffset
)
{
    return 0;
}

NTSTATUS NTAPI Dirtbox::NtSetInformationFile(
    HANDLE FileHandle, LPVOID IoStatusBlock, LPVOID FileInformation, DWORD Length, 
    DWORD FileInformationClass
)
{
    return 0;
}

NTSTATUS NTAPI Dirtbox::NtWriteFile( 
    HANDLE FileHandle, LPVOID Event, LPVOID ApcRoutine, LPVOID ApcContext,
    LPVOID IoStatusBlock, LPVOID Buffer, DWORD Length, PLARGE_INTEGER ByteOffset
)
{
    return 0;
}

/*
// export 24
NTSTATUS NTAPI Dirtbox::ExQueryNonVolatileSetting(
    DWORD ValueIndex, DWORD *Type, PBYTE Value, SIZE_T ValueLength,
    PSIZE_T ResultLength
)
{
    switch(ValueIndex)
    {
    case 7: // Language
        *(DWORD *)Value = 1;
        return 0;
    case 10: // Parental control setting
        *(DWORD *)Value = 0;
        return 0;
    default:
        return -1;
    }
}

*/
