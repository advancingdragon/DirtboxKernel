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
    Spare2Object = 0xA, 
    Spare3Object = 0xB, 
    Spare4Object = 0xC, 
    Spare5Object = 0xD, 
    Spare6Object = 0xE, 
    Spare7Object = 0xF, 
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
    WrPoolAllocation = 0xA, 
    WrDelayExecution = 0xB, 
    WrSuspended = 0xC, 
    WrUserRequest = 0xD, 
    WrEventPair = 0xE, 
    WrQueue = 0xF, 
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
    WrKernel = 0x1A, 
    MaximumWaitReason = 0x1B
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

enum WAIT_TYPE
{ 
    WaitAll = 0, 
    WaitAny = 1
};

enum XC_VALUE_INDEX
{
    XC_TIMEZONE_BIAS = 0x0, 
    XC_TZ_STD_NAME = 0x1, 
    XC_TZ_STD_DATE = 0x2, 
    XC_TZ_STD_BIAS = 0x3, 
    XC_TZ_DLT_NAME = 0x4, 
    XC_TZ_DLT_DATE = 0x5, 
    XC_TZ_DLT_BIAS = 0x6, 
    XC_LANGUAGE = 0x7, 
    XC_VIDEO_FLAGS = 0x8, 
    XC_AUDIO_FLAGS = 0x9, 
    XC_PARENTAL_CONTROL_GAMES = 0xA, 
    XC_PARENTAL_CONTROL_PASSWORD = 0xB, 
    XC_PARENTAL_CONTROL_MOVIES = 0xC, 
    XC_ONLINE_IP_ADDRESS = 0xD, 
    XC_ONLINE_DNS_ADDRESS = 0xE, 
    XC_ONLINE_DEFAULT_GATEWAY_ADDRESS = 0xF, 
    XC_ONLINE_SUBNET_ADDRESS = 0x10, 
    XC_MISC_FLAGS = 0x11, 
    XC_DVD_REGION = 0x12, 
    XC_MAX_OS = 0xFF, 
    XC_FACTORY_START_INDEX = 0x100, 
    XC_FACTORY_SERIAL_NUMBER = 0x100, 
    XC_FACTORY_ETHERNET_ADDR = 0x101, 
    XC_FACTORY_ONLINE_KEY = 0x102, 
    XC_FACTORY_AV_REGION = 0x103, 
    XC_FACTORY_GAME_REGION = 0x104, 
    XC_MAX_FACTORY = 0x1FF, 
    XC_ENCRYPTED_SECTION = 0xFFFE, 
    XC_MAX_ALL = 0xFFFF
};

// Windows NT only enums

enum OBJECT_INFORMATION_CLASS
{
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectAllInformation,
    ObjectDataInformation
};

// typedefs for primitive-sized types
typedef DWORD FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;
typedef BYTE KIRQL, *PKIRQL;
typedef LONG KPRIORITY, *PKPRIORITY;
typedef CHAR KPROCESSOR_MODE;
// don't want to define this yet
typedef PVOID PKQUEUE;
typedef PVOID PTIMER_APC_ROUTINE;

// forward declarations for pointers in earlier structs
typedef struct ANSI_STRING *PANSI_STRING;
typedef struct KAPC *PKAPC;
typedef struct KDPC *PKDPC;
typedef struct KINTERRUPT *PKINTERRUPT;
typedef struct KPCR *PKPCR;
typedef struct KTHREAD *PKTHREAD;
typedef struct KWAIT_BLOCK *PKWAIT_BLOCK;
typedef struct FILE_OBJECT *PFILE_OBJECT;
typedef struct IO_COMPLETION_CONTEXT *PIO_COMPLETION_CONTEXT;
typedef struct IO_STACK_LOCATION *PIO_STACK_LOCATION;
typedef struct IO_STATUS_BLOCK *PIO_STATUS_BLOCK;
typedef struct IRP *PIRP;
typedef struct OBJECT_TYPE *POBJECT_TYPE;
typedef struct DEVICE_OBJECT *PDEVICE_OBJECT;
typedef struct DRIVER_OBJECT *PDRIVER_OBJECT;

// function pointers
typedef VOID (WINAPI *PKDEFERRED_ROUTINE) (PKDPC, PVOID, PVOID, PVOID);
typedef VOID (WINAPI *PKNORMAL_ROUTINE) (PVOID, PVOID, PVOID);
typedef VOID (WINAPI *PKKERNEL_ROUTINE) (PKAPC, PKNORMAL_ROUTINE, PVOID *, PVOID *, PVOID *);
typedef VOID (WINAPI *PKRUNDOWN_ROUTINE) (PKAPC);
typedef BOOLEAN (WINAPI *PKSERVICE_ROUTINE) (PKINTERRUPT, PVOID);
typedef VOID (WINAPI *PKSTART_ROUTINE) (PVOID);
typedef BOOLEAN (WINAPI *PKSYNCHRONIZE_ROUTINE)(PVOID);
typedef VOID (WINAPI *PKSYSTEM_ROUTINE) (PKSTART_ROUTINE, PVOID);

typedef VOID (WINAPI *PIO_APC_ROUTINE)(PVOID, PIO_STATUS_BLOCK, DWORD);
typedef PVOID (WINAPI *OB_ALLOCATE_METHOD)(DWORD, DWORD);
typedef VOID (WINAPI *OB_CLOSE_METHOD)(PVOID, DWORD);
typedef VOID (WINAPI *OB_DELETE_METHOD)(PVOID);
typedef VOID (WINAPI *OB_FREE_METHOD)(PVOID);
typedef LONG (WINAPI *OB_PARSE_METHOD)(PVOID, POBJECT_TYPE, DWORD, PANSI_STRING, 
    PANSI_STRING, PVOID, PVOID*);

typedef VOID (WINAPI *PDRIVER_STARTIO) (PDEVICE_OBJECT, PIRP);
typedef VOID (WINAPI *PDRIVER_DELETEDEVICE) (PDEVICE_OBJECT);
typedef VOID (WINAPI *PDRIVER_DISMOUNTVOLUME) (PDEVICE_OBJECT);
typedef VOID (WINAPI *PDRIVER_DISPATCH) (PDEVICE_OBJECT, PIRP);

// unions
typedef union XBOX_FILE_SEGMENT_ELEMENT // 0x4
{
    PVOID Buffer; // +0x0(0x4)
    DWORD Alignment; // +0x0(0x4)
} PXBOX_FILE_SEGMENT_ELEMENT;

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

typedef struct DISPATCHER_HEADER // 0x10
{
    BYTE Type; // +0x0(0x1)
    BYTE Absolute; // +0x1(0x1)
    BYTE Size; // +0x2(0x1)
    BYTE Inserted; // +0x3(0x1)
    LONG SignalState; // +0x4(0x4)
    LIST_ENTRY WaitListHead; // +0x8(0x8)
} *PDISPATCHER_HEADER;

typedef struct XBOX_CRITICAL_SECTION // 0x1C
{
    DISPATCHER_HEADER Synchronization; // +0x0(0x10)
    LONG LockCount; // +0x10(0x4)
    LONG RecursionCount; // +0x14(0x4)
    PVOID OwningThread; // +0x18(0x4)
} *PXBOX_CRITICAL_SECTION;

typedef struct FILE_FS_SIZE_INFORMATION // 0x18
{
  LARGE_INTEGER TotalAllocationUnits; // +0x0(0x8)
  LARGE_INTEGER AvailableAllocationUnits; // +0x8(0x8)
  DWORD         SectorsPerAllocationUnit; // +0x10(0x4)
  DWORD         BytesPerSector; // +0x14(0x4)
} *PFILE_FS_SIZE_INFORMATION;

struct XBOX_FLOATING_SAVE_AREA // 0x204
{
    WORD ControlWord; // +0x0(0x2)
    WORD StatusWord; // +0x2(0x2)
    WORD TagWord; // +0x4(0x2)
    WORD ErrorOpcode; // +0x6(0x2)
    DWORD ErrorOffset; // +0x8(0x4)
    DWORD ErrorSelector; // +0xC(0x4)
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

typedef struct KDEVICE_QUEUE // 0xC
{
    SHORT Type; // +0x0(0x2)
    BYTE Size; // +0x2(0x1)
    BYTE Busy; // +0x3(0x1)
    LIST_ENTRY DeviceListHead; // +0x4(0x8)
} *PKDEVICE_QUEUE;

typedef struct KDEVICE_QUEUE_ENTRY // 0x10
{
    LIST_ENTRY DeviceListEntry; // +0x0(0x8)
    DWORD SortKey; // +0x8(0x4)
    BYTE Inserted; // +0xC(0x1)
} PKDEVICE_QUEUE_ENTRY;

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

typedef struct KFLOATING_SAVE // 0x20
{
    DWORD ControlWord; // +0x0(0x4)
    DWORD StatusWord; // +0x4(0x4)
    DWORD ErrorOffset; // +0x8(0x4)
    DWORD ErrorSelector; // +0xC(0x4)
    DWORD DataOffset; // +0x10(0x4)
    DWORD DataSelector; // +0x14(0x4)
    DWORD Cr0NpxState; // +0x18(0x4)
    DWORD Spare1; // +0x1C(0x4)
} *PKFLOATING_SAVE;

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
    KIRQL WaitIrql; // +0x54(0x1)
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
    KIRQL NpxIrql; // +0x74(0x1)
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

typedef struct KSYSTEM_TIME // 0xC
{
    DWORD LowPart; // +0x0(0x4)
    LONG High1Time; // +0x4(0x4)
    LONG High2Time; // +0x8(0x4)
} *PKSYSTEM_TIME;

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
    PVOID UniqueThread; // +0x12C(0x4)
    PVOID StartAddress; // +0x130(0x4)
    LIST_ENTRY IrpList; // +0x134(0x8)
    PVOID DebugData; // +0x13C(0x4)
} *PETHREAD;

struct FILE_OBJECT // 0x48
{
    SHORT Type; // +0x0(0x2)
    BYTE DeletePending; // +0x2(0x1)
    BYTE ReadAccess; // +0x2(0x1)
    BYTE WriteAccess; // +0x2(0x1)
    BYTE DeleteAccess; // +0x2(0x1)
    BYTE SharedRead; // +0x2(0x1)
    BYTE SharedWrite; // +0x2(0x1)
    BYTE SharedDelete; // +0x2(0x1)
    BYTE Reserved; // +0x2(0x1)
    BYTE Flags; // +0x3(0x1)
    PDEVICE_OBJECT DeviceObject; // +0x4(0x4)
    PVOID FsContext; // +0x8(0x4)
    PVOID FsContext2; // +0xC(0x4)
    LONG FinalStatus; // +0x10(0x4)
    LARGE_INTEGER CurrentByteOffset; // +0x14(0x8)
    PFILE_OBJECT RelatedFileObject; // +0x1C(0x4)
    PIO_COMPLETION_CONTEXT CompletionContext; // +0x20(0x4)
    LONG LockCount; // +0x24(0x4)
    KEVENT Lock; // +0x28(0x10)
    KEVENT Event; // +0x38(0x10)
};

struct IO_STATUS_BLOCK // 0x8
{
    union
    {
        NTSTATUS Status; // +0x0(0x4)
        PVOID Pointer; // +0x0(0x4)
    };
    DWORD Information; // +0x4(0x4)
};

struct IO_COMPLETION_CONTEXT // 0x8
{
    PVOID Port; // +0x0(0x4)
    PVOID Key; // +0x4(0x4)
};

struct IRP // 0x68
{
    SHORT Type; // +0x0(0x2)
    WORD Size; // +0x2(0x2)
    DWORD Flags; // +0x4(0x4)
    LIST_ENTRY ThreadListEntry; // +0x8(0x8)
    IO_STATUS_BLOCK IoStatus; // +0x10(0x8)
    CHAR StackCount; // +0x18(0x1)
    CHAR CurrentLocation; // +0x19(0x1)
    BYTE PendingReturned; // +0x1A(0x1)
    BYTE Cancel; // +0x1B(0x1)
    PIO_STATUS_BLOCK UserIosb; // +0x1C(0x4)
    PKEVENT UserEvent; // +0x20(0x4)
    union
    {
        struct // 0x8
        {
            PIO_APC_ROUTINE UserApcRoutine; // +0x0(0x4)
            PVOID UserApcContext; // +0x4(0x4)
        } AsynchronousParameters;
        LARGE_INTEGER AllocationSize;
    } Overlay; // +0x28(0x8)
    PVOID UserBuffer; // +0x30(0x4)
    PXBOX_FILE_SEGMENT_ELEMENT SegmentArray; // +0x34(0x4)
    DWORD LockedBufferLength; // +0x38(0x4)
    union
    {
        struct // 0x28
        {
            KDEVICE_QUEUE_ENTRY DeviceQueueEntry; // +0x0(0x10)
            PVOID DriverContext[0x5]; // +0x0(0x14)
            PETHREAD Thread; // +0x14(0x4)
            LIST_ENTRY ListEntry; // +0x18(0x8)
            PIO_STACK_LOCATION CurrentStackLocation; // +0x20(0x4)
            DWORD PacketType; // +0x20(0x4)
            PFILE_OBJECT OriginalFileObject; // +0x24(0x4)
        } Overlay; // +0x0(0x28)
        KAPC Apc; // +0x0(0x28)
        PVOID CompletionKey; // +0x0(0x4)
    } Tail; // +0x3c(0x28)
};

typedef struct XBOX_OBJECT_ATTRIBUTES // 0xC
{
        HANDLE RootDirectory; // +0x0(0x4)
        PANSI_STRING ObjectName; // +0x4(0x4)
        DWORD Attributes; // +0x8(0x4)
} *PXBOX_OBJECT_ATTRIBUTES;

struct OBJECT_TYPE // 0x1c
{
    OB_ALLOCATE_METHOD AllocateProcedure; // +0x0(0x4)
    OB_FREE_METHOD FreeProcedure; // +0x4(0x4)
    OB_CLOSE_METHOD CloseProcedure; // +0x8(0x4)
    OB_DELETE_METHOD DeleteProcedure; // +0xC(0x4)
    OB_PARSE_METHOD ParseProcedure; // +0x10(0x4)
    PVOID DefaultObject; // +0x14(0x4)
    DWORD PoolTag; // +0x18(0x4)
};

struct DEVICE_OBJECT // 0x48
{
    SHORT Type; // +0x0(0x2)
    WORD Size; // +0x2(0x2)
    LONG ReferenceCount; // +0x4(0x4)
    PDRIVER_OBJECT DriverObject; // +0x8(0x4)
    PDEVICE_OBJECT MountedOrSelfDevice; // +0xC(0x4)
    PIRP CurrentIrp; // +0x10(0x4)
    DWORD Flags; // +0x14(0x4)
    PVOID DeviceExtension; // +0x18(0x4)
    BYTE DeviceType; // +0x1C(0x1)
    BYTE StartIoFlags; // +0x1D(0x1)
    CHAR StackSize; // +0x1E(0x1)
    BYTE DeletePending; // +0x1F(0x1)
    DWORD SectorSize; // +0x20(0x4)
    DWORD AlignmentRequirement; // +0x24(0x4)
    KDEVICE_QUEUE DeviceQueue; // +0x28(0xC)
    KEVENT DeviceLock; // +0x34(0x10)
    DWORD StartIoKey; // +0x44(0x4)
};

struct DRIVER_OBJECT // 0x44
{
    PDRIVER_STARTIO DriverStartIo; // +0x0(0x4)
    PDRIVER_DELETEDEVICE DriverDeleteDevice; // +0x4(0x4)
    PDRIVER_DISMOUNTVOLUME DriverDismountVolume; // +0x8(0x4)
    PDRIVER_DISPATCH MajorFunction[0xe]; // +0xC(0x38)
};

typedef struct MM_STATISTICS // 0x24
{
    DWORD Length; // +0x0(0x4)
    DWORD TotalPhysicalPages; // +0x4(0x4)
    DWORD AvailablePages; // +0x8(0x4)
    DWORD VirtualMemoryBytesCommitted; // +0xC(0x4)
    DWORD VirtualMemoryBytesReserved; // +0x10(0x4)
    DWORD CachePagesCommitted; // +0x14(0x4)
    DWORD PoolPagesCommitted; // +0x18(0x4)
    DWORD StackPagesCommitted; // +0x1C(0x4)
    DWORD ImagePagesCommitted; // +0x20(0x4)
} *PMM_STATISTICS;

typedef struct TIME_FIELDS // 0x10
{
    SHORT Year; // +0x0(0x2)
    SHORT Month; // +0x2(0x2)
    SHORT Day; // +0x4(0x2)
    SHORT Hour; // +0x6(0x2)
    SHORT Minute; // +0x8(0x2)
    SHORT Second; // +0xA(0x2)
    SHORT Milliseconds; // +0xC(0x2)
    SHORT Weekday; // +0xE(0x2)
} *PTIME_FIELDS;

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
    DWORD PointerToRawData; // +0xC(0x4)
    DWORD SizeOfRawData; // +0x10(0x4)
    PBYTE SectionName; // +0x14(0x4)
    DWORD SectionReferenceCount; // +0x18(0x4)
    PWORD HeadSharedPageReferenceCount; // +0x1C(0x4)
    PWORD TailSharedPageReferenceCount; // +0x20(0x4)
    BYTE SectionDigest[0x14]; // +0x24(0x14)
} *PXBEIMAGE_SECTION;

// GPU structs

typedef struct NV_VTEST
{
    DWORDLONG Timestamp;
    DWORD Result;
    LONG Status;
} *PNV_VTEST;

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

typedef struct OBJECT_NAME_INFORMATION
{
    UNICODE_STRING Name;
//    WCHAR NameBuffer[MAX_PATH];
} *POBJECT_NAME_INFORMATION;

#endif
