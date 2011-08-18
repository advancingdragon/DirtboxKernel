#ifndef _DIRTBOX_TYPES_H_
#define _DIRTBOX_TYPES_H_

#include <windows.h>

#pragma pack(1)

enum RETURN_FIRMWARE
{
	ReturnFirmwareHalt          = 0x00,
	ReturnFirmwareReboot        = 0x01,
	ReturnFirmwareQuickReboot   = 0x02,
	ReturnFirmwareHard          = 0x03,
	ReturnFirmwareFatal         = 0x04,
	ReturnFirmwareAll           = 0x05
};

enum KINTERRUPT_MODE
{
    LevelSensitive,
    Latched
};

enum TIMER_TYPE
{
	NotificationTimer     = 0,
	SynchronizationTimer  = 1
};

typedef DWORD KWAIT_REASON;
typedef BYTE KIRQL, *PKIRQL;
typedef struct KINTERRUPT *PKINTERRUPT;
typedef struct KDPC *PKDPC;
typedef DWORD FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef VOID (*PKDEFERRED_ROUTINE) (
    PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2
);
typedef BOOLEAN (*PKSERVICE_ROUTINE) (
    PKINTERRUPT Interrupt, PVOID ServiceContext
);
typedef VOID (*PKSTART_ROUTINE) (
    PVOID StartContext1, PVOID StartContext2
);

struct ANSI_STRING {
    WORD Length;
    WORD MaximumLength;
    PSTR Buffer;
};
typedef ANSI_STRING *PANSI_STRING;

struct UNICODE_STRING {
    WORD Length;
    WORD MaximumLength;
    PWSTR Buffer;
};
typedef UNICODE_STRING *PUNICODE_STRING;

struct DISPATCHER_HEADER
{
    BYTE Type;
    BYTE Absolute;
    BYTE Size;
    BYTE Inserted;
    DWORD SignalState;
    LIST_ENTRY WaitListHead;
};

struct KINTERRUPT
{
    PKSERVICE_ROUTINE ServiceRoutine;
    PVOID ServiceContext;
    DWORD BusInterruptLevel;
    DWORD Irql;
    BYTE Connected;
    BYTE ShareVector;
    BYTE Mode;
    BYTE UnknownA;
    DWORD ServiceCount;
    BYTE DispatchCode[88];
};

struct KDPC
{
    SHORT Type;                         // 0x00
    BYTE Inserted;                      // 0x02
    BYTE Padding;                       // 0x03
    LIST_ENTRY DpcListEntry;            // 0x04
    PKDEFERRED_ROUTINE DeferredRoutine; // 0x0C
    PVOID DeferredContext;             // 0x10
    PVOID SystemArgument1;             // 0x14
    PVOID SystemArgument2;             // 0x18
};

struct KTIMER
{
	DISPATCHER_HEADER Header;  // 0x00
	ULARGE_INTEGER DueTime;    // 0x10
	LIST_ENTRY TimerListEntry; // 0x18
	PKDPC Dpc;                 // 0x20
	LONG Period;               // 0x24
};
typedef KTIMER *PKTIMER;

struct HAL_SHUTDOWN_REGISTRATION
{
    PVOID NotificationRoutine;
    DWORD Priority;
    LIST_ENTRY ListEntry;
};
typedef HAL_SHUTDOWN_REGISTRATION *PHAL_SHUTDOWN_REGISTRATION;

struct KEVENT
{
    DISPATCHER_HEADER Header;
};
typedef KEVENT *PKEVENT;

struct XBOX_HARDWARE_INFO
{
    ULONG Flags;
    BYTE Unknown1;
    BYTE Unknown2;
    BYTE Unknown3;
    BYTE Unknown4;
};

struct KPRCB
{
    PVOID CurrentThread;
    PVOID NextThread;
    PVOID IdleThread;
    BYTE Unknown0[0x244];
    DWORD MustBeZero; // offset 0x250
    BYTE Unknown1[0x8];
};
typedef KPRCB *PKPRCB;

struct XBOX_TIB
{
    NT_TIB NtTib;
    XBOX_TIB *Self;
    PKPRCB Prcb;
    DWORD Irql; // actually a byte, need to align
    KPRCB PrcbData;
};

struct OBJECT_ATTRIBUTES
{
        HANDLE RootDirectory;
        PANSI_STRING ObjectName;
        DWORD Attributes;
};
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

struct NT_OBJECT_ATTRIBUTES {
    DWORD Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    DWORD Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
};
typedef NT_OBJECT_ATTRIBUTES *PNT_OBJECT_ATTRIBUTES;

struct IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };

    DWORD_PTR Information;
};
typedef IO_STATUS_BLOCK *PIO_STATUS_BLOCK;

#endif