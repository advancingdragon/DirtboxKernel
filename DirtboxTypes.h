#ifndef _DIRTBOX_TYPES_H_
#define _DIRTBOX_TYPES_H_

#include <windows.h>

enum EVENT_TYPE
{ 
    NotificationEvent = 0x0, 
    SynchronizationEvent = 0x1
};

enum FS_INFORMATION_CLASS
{ 
    FileFsVolumeInformation = 0x1,
    FileFsLabelInformation = 0x2,
    FileFsSizeInformation = 0x3,
    FileFsDeviceInformation = 0x4,
    FileFsAttributeInformation = 0x5,
    FileFsControlInformation = 0x6,
    FileFsFullSizeInformation = 0x7,
    FileFsObjectIdInformation = 0x8,
    FileFsMaximumInformation = 0x9
};

enum KINTERRUPT_MODE
{
    LevelSensitive = 0,
    Latched = 1
};

enum KOBJECTS
{ 
    EventNotificationObject = 0x0, 
    EventSynchronizationObject = 0x1, 
    MutantObject = 0x2, 
    ProcessObject = 0x3, 
    QueueObject = 0x4, 
    SemaphoreObject = 0x5, 
    ThreadObject = 0x6, 
    Spare1Object = 0x7, 
    TimerNotificationObject = 0x8, 
    TimerSynchronizationObject = 0x9, 
    Spare2Object = 0xa, 
    Spare3Object = 0xb, 
    Spare4Object = 0xc, 
    Spare5Object = 0xd, 
    Spare6Object = 0xe, 
    Spare7Object = 0xf, 
    Spare8Object = 0x10, 
    Spare9Object = 0x11, 
    ApcObject = 0x12, 
    DpcObject = 0x13, 
    DeviceQueueObject = 0x14, 
    EventPairObject = 0x15, 
    InterruptObject = 0x16, 
    ProfileObject = 0x17
};

enum KWAIT_REASON
{ 
    Executive = 0x0, 
    FreePage = 0x1, 
    PageIn = 0x2, 
    PoolAllocation = 0x3, 
    DelayExecution = 0x4, 
    Suspended = 0x5, 
    UserRequest = 0x6, 
    WrExecutive = 0x7, 
    WrFreePage = 0x8, 
    WrPageIn = 0x9, 
    WrPoolAllocation = 0xa, 
    WrDelayExecution = 0xb, 
    WrSuspended = 0xc, 
    WrUserRequest = 0xd, 
    WrEventPair = 0xe, 
    WrQueue = 0xf, 
    WrLpcReceive = 0x10, 
    WrLpcReply = 0x11, 
    WrVirtualMemory = 0x12, 
    WrPageOut = 0x13, 
    WrRendezvous = 0x14, 
    WrFsCacheIn = 0x15, 
    WrFsCacheOut = 0x16, 
    Spare4 = 0x17, 
    Spare5 = 0x18, 
    Spare6 = 0x19, 
    WrKernel = 0x1a, 
    MaximumWaitReason = 0x1b, 
};

enum RETURN_FIRMWARE
{
	ReturnFirmwareHalt = 0,
	ReturnFirmwareReboot = 1,
	ReturnFirmwareQuickReboot = 2,
	ReturnFirmwareHard = 3,
	ReturnFirmwareFatal = 4,
	ReturnFirmwareAll = 5
};

enum TIMER_TYPE
{
	NotificationTimer     = 0,
	SynchronizationTimer  = 1
};

// typedefs for primitive-sized types
typedef DWORD FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;
typedef BYTE KIRQL, *PKIRQL;
// don't want to define this yet
typedef PVOID PKQUEUE;

// forward declarations for pointers in earlier structs
typedef struct KAPC *PKAPC;
typedef struct KDPC *PKDPC;
typedef struct KINTERRUPT *PKINTERRUPT;
typedef struct KPCR *PKPCR;
typedef struct KTHREAD *PKTHREAD;
typedef struct KWAIT_BLOCK *PKWAIT_BLOCK;

// function pointers
typedef VOID (WINAPI *PKDEFERRED_ROUTINE) (PKDPC, PVOID, PVOID, PVOID);
typedef VOID (WINAPI *PKNORMAL_ROUTINE) (PVOID, PVOID, PVOID);
typedef VOID (WINAPI *PKKERNEL_ROUTINE) (PKAPC, PKNORMAL_ROUTINE, PVOID *, PVOID *, PVOID *);
typedef VOID (WINAPI *PKRUNDOWN_ROUTINE) (PKAPC);
typedef BOOLEAN (WINAPI *PKSERVICE_ROUTINE) (PKINTERRUPT, PVOID);
typedef VOID (WINAPI *PKSTART_ROUTINE) (PVOID);
typedef VOID (WINAPI *PKSYSTEM_ROUTINE) (PKSTART_ROUTINE, PVOID);

// structs
typedef struct ANSI_STRING // 0x8
{
    WORD Length; // +0x0(0x2)
    WORD MaximumLength; // +0x2(0x2)
    PSTR Buffer; // +0x4(0x4)
} *PANSI_STRING;

typedef struct UNICODE_STRING // 0x8
{
    WORD Length; // +0x0(0x2)
    WORD MaximumLength; // +0x2(0x2)
    PWSTR Buffer; // +0x4(0x4)
} *PUNICODE_STRING;

struct DISPATCHER_HEADER // 0x10
{
    BYTE Type; // +0x0(0x1)
    BYTE Absolute; // +0x1(0x1)
    BYTE Size; // +0x2(0x1)
    BYTE Inserted; // +0x3(0x1)
    LONG SignalState; // +0x4(0x4)
    LIST_ENTRY WaitListHead; // +0x8(0x8)
};

typedef struct FILE_FS_SIZE_INFORMATION // 0x18
{
  LARGE_INTEGER TotalAllocationUnits; // +0x0(0x8)
  LARGE_INTEGER AvailableAllocationUnits; // +0x8(0x8)
  ULONG         SectorsPerAllocationUnit; // +0x10(0x4)
  ULONG         BytesPerSector; // +0x14(0x4)
} *PFILE_FS_SIZE_INFORMATION;

struct XBOX_FLOATING_SAVE_AREA // 0x204
{
    WORD ControlWord; // +0x0(0x2)
    WORD StatusWord; // +0x2(0x2)
    WORD TagWord; // +0x4(0x2)
    WORD ErrorOpcode; // +0x6(0x2)
    DWORD ErrorOffset; // +0x8(0x4)
    DWORD ErrorSelector; // +0xc(0x4)
    DWORD DataOffset; // +0x10(0x4)
    DWORD DataSelector; // +0x14(0x4)
    DWORD MXCsr; // +0x18(0x4)
    DWORD Reserved2; // +0x1C(0x4)
    BYTE RegisterArea[128]; // +0x20(0x80)
    BYTE XmmRegisterArea[128]; // +0xA0(0x80)
    BYTE Reserved4[224]; // +0x120(0xE0)
    DWORD Cr0NpxState; // +0x200(0x4)
};

struct FX_SAVE_AREA // 0x210
{
    XBOX_FLOATING_SAVE_AREA FloatSave; // +0x0(0x204)
    DWORD Align16Byte[3]; // +0x204(0xC)
};

typedef struct HAL_SHUTDOWN_REGISTRATION // 0x10
{
    PVOID NotificationRoutine; // +0x0(0x4)
    DWORD Priority; // +0x4(0x4)
    LIST_ENTRY ListEntry; // +0x8(0x8)
} *PHAL_SHUTDOWN_REGISTRATION;

typedef struct IO_STATUS_BLOCK // 0x8
{
    union
    {
        NTSTATUS Status; // +0x0(0x4)
        PVOID Pointer; // +0x0(0x4)
    };
    DWORD Information; // +0x4(0x4)
} *PIO_STATUS_BLOCK;

struct KAPC // 0x28
{
    SHORT Type; // +0x0(0x2)
    CHAR ApcMode; // +0x2(0x1)
    BYTE Inserted; // +0x3(0x1)
    PKTHREAD Thread; // +0x4(0x4)
    LIST_ENTRY ApcListEntry; // +0x8(0x8)
    PKKERNEL_ROUTINE KernelRoutine; // +0x10(0x4)
    PKRUNDOWN_ROUTINE RundownRoutine; // +0x14(0x4)
    PKNORMAL_ROUTINE NormalRoutine; // +0x18(0x4)
    PVOID NormalContext; // +0x1C(0x4)
    PVOID SystemArgument1; // +0x20(0x4)
    PVOID SystemArgument2; // +0x24(0x4)
};

struct KAPC_STATE // 0x18
{
    LIST_ENTRY ApcListHead[2]; // +0x0(0x10)
    PVOID Process; // +0x10(0x4)
    BYTE KernelApcInProgress; // +0x14(0x1)
    BYTE KernelApcPending; // +0x15(0x1)
    BYTE UserApcPending; // +0x16(0x1)
    BYTE ApcQueueable; // +0x17(0x1)
};

struct KDPC // 0x1C
{
    SHORT Type; // +0x0(0x2)
    BYTE Inserted; // +0x2(0x1)
    BYTE Padding; // +0x3(0x1)
    LIST_ENTRY DpcListEntry; // +0x4(0x8)
    PKDEFERRED_ROUTINE DeferredRoutine; // +0xC(0x4)
    PVOID DeferredContext; // +0x10(0x4)
    PVOID SystemArgument1; // +0x14(0x4)
    PVOID SystemArgument2; // +0x18(0x4)
};

typedef struct KEVENT // 0x10
{
    DISPATCHER_HEADER Header; // +0x0(0x10)
} *PKEVENT;

struct KINTERRUPT // 0x70
{
    PKSERVICE_ROUTINE ServiceRoutine; // +0x0(0x4)
    PVOID ServiceContext; // +0x4(0x4)
    DWORD BusInterruptLevel; // +0x8(0x4)
    DWORD Irql; // +0xC(0x4)
    BYTE Connected; // +0x10(0x1)
    BYTE ShareVector; // +0x11(0x1)
    BYTE Mode; // +0x12(0x1)
    DWORD ServiceCount; // +0x14(0x4)
    DWORD DispatchCode[22]; // +0x18(0x58)
};

struct KSEMAPHORE // 0x14
{
    DISPATCHER_HEADER Header; // +0x0(0x10)
    LONG Limit; // +0x10(0x4)
};

typedef struct KTIMER // 0x28
{
    DISPATCHER_HEADER Header; // +0x0(0x10)
    ULARGE_INTEGER DueTime; // +0x10(0x8)
    LIST_ENTRY TimerListEntry; // +0x18(0x8)
    PKDPC Dpc; // +0x20(0x4)
    LONG Period; // +0x24(0x4)
} *PKTIMER;

struct KWAIT_BLOCK // 0x18
{
    LIST_ENTRY WaitListEntry; // +0x0(0x8)
    PKTHREAD Thread; // +0x8(0x4)
    PVOID Object; // +0xC(0x4)
    PKWAIT_BLOCK NextWaitBlock; // +0x10(0x4)
    WORD WaitKey; // +0x14(0x2)
    WORD WaitType; // +0x16(0x2)
};

struct KTHREAD // 0x110
{
    DISPATCHER_HEADER Header; // +0x0(0x10)
    LIST_ENTRY MutantListHead; // +0x10(0x8)
    DWORD KernelTime; // +0x18(0x4)
    PVOID StackBase; // +0x1C(0x4)
    PVOID StackLimit; // +0x20(0x4)
    PVOID KernelStack; // +0x24(0x4)
    PVOID TlsData; // +0x28(0x4)
    BYTE State; // +0x2C(0x1)
    BYTE Alerted[2]; // +0x2D(0x2)
    BYTE Alertable; // +0x2F(0x1)
    BYTE NpxState; // +0x30(0x1)
    CHAR Saturation; // +0x31(0x1)
    CHAR Priority; // +0x32(0x1)
    BYTE Padding; // +0x33(0x1)
    KAPC_STATE ApcState; // +0x34(0x18)
    DWORD ContextSwitches; // +0x4C(0x4)
    LONG WaitStatus; // +0x50(0x4)
    BYTE WaitIrql; // +0x54(0x1)
    CHAR WaitMode; // +0x55(0x1)
    BYTE WaitNext; // +0x56(0x1)
    BYTE WaitReason; // +0x57(0x1)
    PKWAIT_BLOCK WaitBlockList; // +0x58(0x4)
    LIST_ENTRY WaitListEntry; // +0x5C(0x8)
    DWORD WaitTime; // +0x64(0x4)
    DWORD KernelApcDisable; // +0x68(0x4)
    LONG Quantum; // +0x6C(0x4)
    CHAR BasePriority; // +0x70(0x1)
    BYTE DecrementCount; // +0x71(0x1)
    CHAR PriorityDecrement; // +0x72(0x1)
    BYTE DisableBoost; // +0x73(0x1)
    BYTE NpxIrql; // +0x74(0x1)
    CHAR SuspendCount; // +0x75(0x1)
    BYTE Preempted; // +0x76(0x1)
    BYTE HasTerminated; // +0x77(0x1)
    PKQUEUE Queue; // +0x78(0x4)
    LIST_ENTRY QueueListEntry; // +0x7C(0x8)
    KTIMER Timer; // +0x88(0x28)
    KWAIT_BLOCK TimerWaitBlock; // +0xB0(0x18)
    KAPC SuspendApc; // +0xC8(0x28)
    KSEMAPHORE SuspendSemaphore; // +0xF0(0x14)
    LIST_ENTRY ThreadListEntry; // +0x104(0x8)
};

typedef struct KPRCB // 0x25C
{
    PKTHREAD CurrentThread; // +0x0(0x4)
    PKTHREAD NextThread; // +0x4(0x4)
    PKTHREAD IdleThread; // +0x8(0x4)
    PKTHREAD NpxThread; // +0xC(0x4)
    DWORD InterruptCount; // +0x10(0x4)
    DWORD DpcTime; // +0x14(0x4)
    DWORD InterruptTime; // +0x18(0x4)
    DWORD DebugDpcTime; // +0x1C(0x4)
    DWORD KeContextSwitches; // +0x20(0x4)
    DWORD DpcInterruptRequested; // +0x24(0x4)
    LIST_ENTRY DpcListHead; // +0x28(0x8)
    DWORD DpcRoutineActive; // +0x30(0x4)
    PVOID DpcStack; // +0x34(0x4)
    DWORD QuantumEnd; // +0x38(0x4)
    FX_SAVE_AREA NpxSaveArea; // +0x3C(0x210)
    PVOID DmEnetFunc; // +0x24C(0x4)
    PVOID DebugMonitorData; // +0x250(0x4)
    PVOID DebugHaltThread; // +0x254(0x4)
    PVOID DebugDoubleFault; // +0x258(0x4)
} *PKPRCB;

struct KPCR // 0x284
{
    NT_TIB NtTib; // +0x0(0x1C)
    PKPCR SelfPcr; // +0x1C(0x4)
    PKPRCB Prcb; // +0x20(0x4)
    KIRQL Irql; // +0x24(0x1)
    KPRCB PrcbData; // +0x28(0x25C)
};

typedef struct ETHREAD // 0x140
{
    KTHREAD Tcb; // +0x0(0x110)
    LARGE_INTEGER CreateTime; // +0x110(0x8)
    LARGE_INTEGER ExitTime; // +0x118(0x8)
    union
    {
        LONG ExitStatus; // +0x120(0x4)
        PVOID OfsChain; // +0x120(0x4)
    };
    union
    {
        LIST_ENTRY ReaperListEntry; // +0x124(0x8)
        LIST_ENTRY ActiveTimerListHead; // +0x124(0x8)
    };
    PVOID UniqueThread; // +0x12c(0x4)
    PVOID StartAddress; // +0x130(0x4)
    LIST_ENTRY IrpList; // +0x134(0x8)
    PVOID DebugData; // +0x13c(0x4)
} *PETHREAD;

typedef struct XBOX_CRITICAL_SECTION // 0x1C
{
    DISPATCHER_HEADER Synchronization; // +0x0(0x10)
    LONG LockCount; // +0x10(0x4)
    LONG RecursionCount; // +0x14(0x4)
    PVOID OwningThread; // +0x18(0x4)
} *PXBOX_CRITICAL_SECTION;

typedef struct XBOX_OBJECT_ATTRIBUTES // 0xC
{
        HANDLE RootDirectory; // +0x0(0x4)
        PANSI_STRING ObjectName; // +0x4(0x4)
        DWORD Attributes; // +0x8(0x4)
} *PXBOX_OBJECT_ATTRIBUTES;

struct XBOX_HARDWARE_INFO // 0x8
{
    DWORD Flags; // +0x0(0x4)
    BYTE GpuRevision; // +0x4(0x1)
    BYTE McpRevision; // +0x5(0x1)
    BYTE reserved[2]; // +0x6(0x2)
};

struct XBOX_KRNL_VERSION // 0x8
{
    WORD Major; // +0x0(0x2)
    WORD Minor; // +0x2(0x2)
    WORD Build; // +0x4(0x2)
    WORD Qfe; // +0x6(0x2)
};

typedef struct XBEIMAGE_SECTION // 0x38
{
    DWORD SectionFlags; // +0x0(0x4)
    DWORD VirtualAddress; // +0x4(0x4)
    DWORD VirtualSize; // +0x8(0x4)
    DWORD PointerToRawData; // +0xc(0x4)
    DWORD SizeOfRawData; // +0x10(0x4)
    PBYTE SectionName; // +0x14(0x4)
    DWORD SectionReferenceCount; // +0x18(0x4)
    PWORD HeadSharedPageReferenceCount; // +0x1c(0x4)
    PWORD TailSharedPageReferenceCount; // +0x20(0x4)
    BYTE SectionDigest[0x14]; // +0x24(0x14)
} *PXBEIMAGE_SECTION;

// Windows NT structs

typedef struct OBJECT_ATTRIBUTES
{
    DWORD Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    DWORD Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} *POBJECT_ATTRIBUTES;

#endif
