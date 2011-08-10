#ifndef DIRTBOX_TYPES_H
#define DIRTBOX_TYPES_H

#include <windows.h>

#pragma pack(1)

enum KINTERRUPT_MODE { LevelSensitive, Latched };

typedef DWORD KWAIT_REASON;
typedef BYTE KIRQL, *PKIRQL;
typedef struct KINTERRUPT *PKINTERRUPT;
typedef struct KDPC *PKDPC;

typedef BOOLEAN (*PKSERVICE_ROUTINE) (
    PKINTERRUPT Interrupt, LPVOID ServiceContext
);
typedef VOID (*PKDEFERRED_ROUTINE) (
    PKDPC Dpc, LPVOID DeferredContext, LPVOID SystemArgument1, LPVOID SystemArgument2
);

struct KINTERRUPT
{
    PKSERVICE_ROUTINE ServiceRoutine;
    LPVOID ServiceContext;
    DWORD BusInterruptLevel;
    DWORD Irql;
    BYTE Connected;
    BYTE ShareVector;
    BYTE Mode;
    BYTE UnknownA;
    DWORD ServiceCount;
    BYTE DispatchCode[88];
};

struct HAL_SHUTDOWN_REGISTRATION
{
    LPVOID NotificationRoutine;
    DWORD Priority;
    LIST_ENTRY ListEntry;
};
typedef HAL_SHUTDOWN_REGISTRATION *PHAL_SHUTDOWN_REGISTRATION;

struct KDPC
{
    SHORT Type;                         // 0x00
    BYTE Inserted;                      // 0x02
    BYTE Padding;                       // 0x03
    LIST_ENTRY DpcListEntry;            // 0x04
    PKDEFERRED_ROUTINE DeferredRoutine; // 0x0C
    LPVOID DeferredContext;             // 0x10
    LPVOID SystemArgument1;             // 0x14
    LPVOID SystemArgument2;             // 0x18
};

struct DISPATCHER_HEADER
{
    BYTE Type;
    BYTE Absolute;
    BYTE Size;
    BYTE Inserted;
    DWORD SignalState;
    LIST_ENTRY WaitListHead;
};

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
    LPVOID CurrentThread;
    LPVOID NextThread;
    LPVOID IdleThread;
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

#endif