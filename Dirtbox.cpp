#include "Dirtbox.h"

namespace Dirtbox
{
    CRITICAL_SECTION PrintLock;
    DWORD PrintReturn;
    CHAR PrintStringError[] = "Error: ";
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
    if (!NT_SUCCESS(AllocateTib(20)))
        FatalPrint("Initialize: Failed to allocate initial TIB.");
    InitializeGraphics();

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
        case 24:
            KernelImageThunks[i] = (DWORD)&ExQueryNonVolatileSetting;
            break;
        case 40:
            KernelImageThunks[i] = (DWORD)&HalDiskCachePartitionCount;
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
        case 67:
            KernelImageThunks[i] = (DWORD)&IoCreateSymbolicLink;
            break;
        case 69:
            KernelImageThunks[i] = (DWORD)&IoDeleteSymbolicLink;
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
            KernelImageThunks[i] = (DWORD)&XboxHDKey;
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

    DebugPrint("Initialize: All initialized successfully, starting app.");
    SwapTibs();

    PMAIN_ROUTINE MainRoutine = (PMAIN_ROUTINE)(XBE_ENTRY_POINT ^ XBE_ENTRY_POINT_KEY);
    MainRoutine();

    SwapTibs();
    FreeTib();
}

// The reason DebugPrint and FatalPrint are in assembly and declared NAKED
// is there is no other way to pass variadic parameters to printf
VOID NAKED Dirtbox::DebugPrint(PSTR Format, ...)
{
    __asm
    {
        // EnterCriticalSection(&PrintLock)
        push offset PrintLock
        call dword ptr [EnterCriticalSection]

        // printf(<original parameters to DebugPrint>)
        pop dword ptr [PrintReturn]
        call dword ptr [printf]
        push dword ptr [PrintReturn]

        // putchar('\n')
        push '\n'
        call dword ptr [putchar]
        add esp, 4

        // LeaveCriticalSection(&PrintLock)
        push offset PrintLock
        call dword ptr [LeaveCriticalSection]
        ret
    }
}

VOID NAKED Dirtbox::FatalPrint(PSTR Format, ...)
{
    __asm
    {
        // EnterCriticalSection(&PrintLock)
        push offset PrintLock
        call dword ptr [EnterCriticalSection]

        // printf("Error: ")
        push offset PrintStringError
        call dword ptr [printf]
        add esp, 4

        // printf(<original parameters to FatalPrint>)
        pop dword ptr [PrintReturn]
        call dword ptr [printf]
        push dword ptr [PrintReturn]

        // putchar('\n')
        push '\n'
        call dword ptr [putchar]
        add esp, 4

        // LeaveCriticalSection(&PrintLock)
        push offset PrintLock
        call dword ptr [LeaveCriticalSection]

        // exit(1)
        push 1
        call dword ptr [exit]
        add esp, 4
    }
}