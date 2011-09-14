// Main entry point

#include "DirtboxDefines.h"
#include "DirtboxEmulator.h"
#include "DirtboxKernel.h"
#include <stdio.h>

namespace Dirtbox
{
    CRITICAL_SECTION PrintLock;
}

BOOL WINAPI DllMain(
    HINSTANCE hInstDll, DWORD fdwReason, PVOID fImpLoad
)
{
    return TRUE;
}

VOID WINAPI Dirtbox::Initialize()
{
    // Initialize printing locks
    InitializeCriticalSection(&PrintLock);

    InitializeException();
    InitializeDummyKernel();
    InitializeDrives();
    InitializeThreading();
    __writefsword(NT_TIB_USER_POINTER, GetFS());
    InitializeGraphics();
    InitializeKernel();

    DebugPrint("Initialize: All initialized successfully, starting app.");
    SwapTibs();

    PMAIN_ROUTINE MainRoutine = (PMAIN_ROUTINE)(XBE_ENTRY_POINT ^ XBE_ENTRY_POINT_KEY);
    MainRoutine();

    SwapTibs();
    FreeTib();
}

VOID Dirtbox::InitializeKernel()
{
    // Initialize kernel globals
    ExEventObjectType.AllocateProcedure = &ExAllocatePoolWithTag;
    ExEventObjectType.FreeProcedure = &ExFreePool;
    ExEventObjectType.CloseProcedure = NULL;
    ExEventObjectType.DeleteProcedure = NULL;
    ExEventObjectType.ParseProcedure = NULL;
    ExEventObjectType.DefaultObject = NULL;
    ExEventObjectType.PoolTag = 0x76657645;

    HalDiskCachePartitionCount = 3;

    HalDiskModelNumber.Length = 0;
    HalDiskModelNumber.MaximumLength = 0;
    HalDiskModelNumber.Buffer = NULL;

    HalDiskSerialNumber.Length = 0;
    HalDiskSerialNumber.MaximumLength = 0;
    HalDiskSerialNumber.Buffer = NULL;

    IoFileObjectType.AllocateProcedure = &ExAllocatePoolWithTag;
    IoFileObjectType.FreeProcedure = &ExFreePool;
    IoFileObjectType.CloseProcedure = NULL; // TODO
    IoFileObjectType.DeleteProcedure = NULL; // TODO
    IoFileObjectType.ParseProcedure = NULL; // TODO
    IoFileObjectType.DefaultObject = (PVOID)0x38;
    IoFileObjectType.PoolTag = 0x656C6946;

    LaunchDataPage = 0;

    XboxHardwareInfo.Flags = 0x202;
    XboxHardwareInfo.GpuRevision = 0;
    XboxHardwareInfo.McpRevision = 0;

    memset(XboxHDKey, 0, 16);

    XboxKrnlVersion.Major = 1;
    XboxKrnlVersion.Minor = 0;
    XboxKrnlVersion.Build = 0x154F;
    XboxKrnlVersion.Qfe = 0x8001;

    // replace kernel import ordinals with pointer to our functions
    PDWORD KernelImageThunks = (PDWORD)(XBE_KERNEL_THUNK ^ XBE_KERNEL_THUNK_KEY);
    DWORD Thunk;
    for (int i = 0; Thunk = KernelImageThunks[i] & 0x7FFFFFFF, Thunk != NULL; i++)
    {
        switch (Thunk)
        {
        case 1:
            KernelImageThunks[i] = (DWORD)&AvGetSavedDataAddress;
            break;
        case 2:
            KernelImageThunks[i] = (DWORD)&AvSendTVEncoderOption;
            break;
        case 3:
            KernelImageThunks[i] = (DWORD)&AvSetDisplayMode;
            break;
        case 4:
            KernelImageThunks[i] = (DWORD)&AvSetSavedDataAddress;
            break;
        case 8:
            KernelImageThunks[i] = (DWORD)&DbgPrint;
            break;
        case 14:
            KernelImageThunks[i] = (DWORD)&ExAllocatePool;
            break;
        case 15:
            KernelImageThunks[i] = (DWORD)&ExAllocatePoolWithTag;
            break;
        case 16:
            KernelImageThunks[i] = (DWORD)&ExEventObjectType;
            break;
        case 17:
            KernelImageThunks[i] = (DWORD)&ExFreePool;
            break;
        case 23:
            KernelImageThunks[i] = (DWORD)&ExQueryPoolBlockSize;
            break;
        case 24:
            KernelImageThunks[i] = (DWORD)&ExQueryNonVolatileSetting;
            break;
        case 40:
            KernelImageThunks[i] = (DWORD)&HalDiskCachePartitionCount;
            break;
        case 41:
            KernelImageThunks[i] = (DWORD)&HalDiskModelNumber;
            break;
        case 42:
            KernelImageThunks[i] = (DWORD)&HalDiskSerialNumber;
            break;
        case 44:
            KernelImageThunks[i] = (DWORD)&HalGetInterruptVector;
            break;
        case 46:
            KernelImageThunks[i] = (DWORD)&HalReadWritePCISpace;
            break;
        case 47:
            KernelImageThunks[i] = (DWORD)&HalRegisterShutdownNotification;
            break;
        case 49:
            KernelImageThunks[i] = (DWORD)&HalReturnToFirmware;
            break;
        case 62:
            KernelImageThunks[i] = (DWORD)&IoBuildSynchronousFsdRequest;
            break;
        case 65:
            KernelImageThunks[i] = (DWORD)&IoCreateDevice;
            break;
        case 67:
            KernelImageThunks[i] = (DWORD)&IoCreateSymbolicLink;
            break;
        case 69:
            KernelImageThunks[i] = (DWORD)&IoDeleteSymbolicLink;
            break;
        case 71:
            KernelImageThunks[i] = (DWORD)&IoFileObjectType;
            break;
        case 74:
            KernelImageThunks[i] = (DWORD)&IoInvalidDeviceRequest;
            break;
        case 81:
            KernelImageThunks[i] = (DWORD)&IoStartNextPacket;
            break;
        case 83:
            KernelImageThunks[i] = (DWORD)&IoStartPacket;
            break;
        case 84:
            KernelImageThunks[i] = (DWORD)&IoSynchronousDeviceIoControlRequest;
            break;
        case 85:
            KernelImageThunks[i] = (DWORD)&IoSynchronousFsdRequest;
            break;
        case 86:
            KernelImageThunks[i] = (DWORD)&IofCallDriver;
            break;
        case 87:
            KernelImageThunks[i] = (DWORD)&IofCompleteRequest;
            break;
        case 95:
            KernelImageThunks[i] = (DWORD)&KeBugCheck;
            break;
        case 98:
            KernelImageThunks[i] = (DWORD)&KeConnectInterrupt;
            break;
        case 99:
            KernelImageThunks[i] = (DWORD)&KeDelayExecutionThread;
            break;
        case 100:
            KernelImageThunks[i] = (DWORD)&KeDisconnectInterrupt;
            break;
        case 107:
            KernelImageThunks[i] = (DWORD)&KeInitializeDpc;
            break;
        case 109:
            KernelImageThunks[i] = (DWORD)&KeInitializeInterrupt;
            break;
        case 113:
            KernelImageThunks[i] = (DWORD)&KeInitializeTimerEx;
            break;
        case 119:
            KernelImageThunks[i] = (DWORD)&KeInsertQueueDpc;
            break;
        case 128:
            KernelImageThunks[i] = (DWORD)&KeQuerySystemTime;
            break;
        case 129:
            KernelImageThunks[i] = (DWORD)&KeRaiseIrqlToDpcLevel;
            break;
        case 145:
            KernelImageThunks[i] = (DWORD)&KeSetEvent;
            break;
        case 149:
            KernelImageThunks[i] = (DWORD)&KeSetTimer;
            break;
        case 159:
            KernelImageThunks[i] = (DWORD)&KeWaitForSingleObject;
            break;
        case 161:
            KernelImageThunks[i] = (DWORD)&KfLowerIrql;
            break;
        case 164:
            KernelImageThunks[i] = (DWORD)&LaunchDataPage;
            break;
        case 165:
            KernelImageThunks[i] = (DWORD)&MmAllocateContiguousMemory;
            break;
        case 166:
            KernelImageThunks[i] = (DWORD)&MmAllocateContiguousMemoryEx;
            break;
        case 168:
            KernelImageThunks[i] = (DWORD)&MmClaimGpuInstanceMemory;
            break;
        case 171:
            KernelImageThunks[i] = (DWORD)&MmFreeContiguousMemory;
            break;
        case 178:
            KernelImageThunks[i] = (DWORD)&MmPersistContiguousMemory;
            break;
        case 179:
            KernelImageThunks[i] = (DWORD)&MmQueryAddressProtect;
            break;
        case 180:
            KernelImageThunks[i] = (DWORD)&MmQueryAllocationSize;
            break;
        case 182:
            KernelImageThunks[i] = (DWORD)&MmSetAddressProtect;
            break;
        case 184:
            KernelImageThunks[i] = (DWORD)&NtAllocateVirtualMemory;
            break;
        case 187:
            KernelImageThunks[i] = (DWORD)&NtClose;
            break;
        case 190:
            KernelImageThunks[i] = (DWORD)&NtCreateFile;
            break;
        case 196:
            KernelImageThunks[i] = (DWORD)&NtDeviceIoControlFile;
            break;
        case 198:
            KernelImageThunks[i] = (DWORD)&NtFlushBuffersFile;
            break;
        case 199:
            KernelImageThunks[i] = (DWORD)&NtFreeVirtualMemory;
            break;
        case 200:
            KernelImageThunks[i] = (DWORD)&NtFsControlFile;
            break;
        case 202:
            KernelImageThunks[i] = (DWORD)&NtOpenFile;
            break;
        case 203:
            KernelImageThunks[i] = (DWORD)&NtOpenSymbolicLinkObject;
            break;
        case 211:
            KernelImageThunks[i] = (DWORD)&NtQueryInformationFile;
            break;
        case 215:
            KernelImageThunks[i] = (DWORD)&NtQuerySymbolicLinkObject;
            break;
        case 217:
            KernelImageThunks[i] = (DWORD)&NtQueryVirtualMemory;
            break;
        case 218:
            KernelImageThunks[i] = (DWORD)&NtQueryVolumeInformationFile;
            break;
        case 219:
            KernelImageThunks[i] = (DWORD)&NtReadFile;
            break;
        case 226:
            KernelImageThunks[i] = (DWORD)&NtSetInformationFile;
            break;
        case 233:
            KernelImageThunks[i] = (DWORD)&NtWaitForSingleObject;
            break;
        case 234:
            KernelImageThunks[i] = (DWORD)&NtWaitForSingleObjectEx;
            break;
        case 236:
            KernelImageThunks[i] = (DWORD)&NtWriteFile;
            break;
        case 255:
            KernelImageThunks[i] = (DWORD)&PsCreateSystemThreadEx;
            break;
        case 258:
            KernelImageThunks[i] = (DWORD)&PsTerminateSystemThread;
            break;
        case 269:
            KernelImageThunks[i] = (DWORD)&RtlCompareMemoryUlong;
            break;
        case 277:
            KernelImageThunks[i] = (DWORD)&RtlEnterCriticalSection;
            break;
        case 279:
            KernelImageThunks[i] = (DWORD)&RtlEqualString;
            break;
        case 289:
            KernelImageThunks[i] = (DWORD)&RtlInitAnsiString;
            break;
        case 291:
            KernelImageThunks[i] = (DWORD)&RtlInitializeCriticalSection;
            break;
        case 294:
            KernelImageThunks[i] = (DWORD)&RtlLeaveCriticalSection;
            break;
        case 301:
            KernelImageThunks[i] = (DWORD)&RtlNtStatusToDosError;
            break;
        case 302:
            KernelImageThunks[i] = (DWORD)&RtlRaiseException;
            break;
        case 312:
            KernelImageThunks[i] = (DWORD)&RtlUnwind;
            break;
        case 322:
            KernelImageThunks[i] = (DWORD)&XboxHardwareInfo;
            break;
        case 323:
            KernelImageThunks[i] = (DWORD)XboxHDKey; // Array is already pointer
            break;
        case 324:
            KernelImageThunks[i] = (DWORD)&XboxKrnlVersion;
            break;
        case 326:
            KernelImageThunks[i] = (DWORD)&XeImageFileName;
            break;
        case 327:
            KernelImageThunks[i] = (DWORD)&XeLoadSection;
            break;
        case 328:
            KernelImageThunks[i] = (DWORD)&XeUnloadSection;
            break;
        case 335:
            KernelImageThunks[i] = (DWORD)&XcSHAInit;
            break;
        case 336:
            KernelImageThunks[i] = (DWORD)&XcSHAUpdate;
            break;
        case 337:
            KernelImageThunks[i] = (DWORD)&XcSHAFinal;
            break;
        case 340:
            KernelImageThunks[i] = (DWORD)&XcHMAC;
            break;
        case 357:
            KernelImageThunks[i] = (DWORD)&IdexChannelObject;
            break;
        case 360:
            KernelImageThunks[i] = (DWORD)&HalInitiateShutdown;
            break;
        default:
            FatalPrint("Initialize: Unimplemented kernel function %i.", Thunk);
        }
    }
}

// NOTE: Do we need to call fflush(stdout) here?
VOID Dirtbox::DebugPrint(PSTR Format, ...)
{
    EnterCriticalSection(&PrintLock);

    va_list Args;
    va_start(Args, Format);
    vprintf(Format, Args);
    va_end(Args);
    putchar('\n');

    LeaveCriticalSection(&PrintLock);
}

VOID Dirtbox::FatalPrint(PSTR Format, ...)
{
    EnterCriticalSection(&PrintLock);

    printf("Error: ");
    va_list Args;
    va_start(Args, Format);
    vprintf(Format, Args);
    va_end(Args);
    putchar('\n');

    LeaveCriticalSection(&PrintLock);

    exit(1);
}