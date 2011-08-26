// Threading - thread local storage and thread information block

#include "DirtboxDefines.h"
#include "DirtboxEmulator.h"
#include "Native.h"
#include <malloc.h>

namespace Dirtbox
{
    CRITICAL_SECTION ThreadingLock;
    BOOL FreeDescriptors[MAXIMUM_XBOX_THREADS];

    NTSTATUS AllocateLdtEntry(PWORD Selector, DWORD Base, DWORD LimitSize);
    NTSTATUS FreeLdtEntry(WORD Selector);
}

VOID Dirtbox::InitializeThreading()
{
    InitializeCriticalSection(&ThreadingLock);

    for(int i = 0; i < MAXIMUM_XBOX_THREADS; i++)
        FreeDescriptors[i] = TRUE;

    DebugPrint("InitializeThreading: Threading initialized successfully.");
}

WORD Dirtbox::GetFS()
{
    __asm
    {
        mov ax, fs
    }
}

// The million dollar question here is: is NT_TIB.StackBase required 
// to be aligned?
UINT WINAPI Dirtbox::ShimCallback(PVOID ShimContextPtr)
{
    SHIM_CONTEXT ShimContext = *(PSHIM_CONTEXT)ShimContextPtr;
    free(ShimContextPtr);

    PNT_TIB OldNtTib = (PNT_TIB)__readfsdword(NT_TIB_SELF);
    PBYTE Tls;
    ETHREAD Ethread;
    KPCR Kpcr;

    Tls = (PBYTE)_alloca(ShimContext.TlsDataSize);
    memset(&Ethread, 0, sizeof(ETHREAD));
    memset(&Kpcr, 0, sizeof(KPCR));

    // Initialize Ethread structure
    Ethread.Tcb.TlsData = Tls;
    Ethread.UniqueThread = (PVOID)GetCurrentThreadId();

    // Initialize subsystem independent part
    Kpcr.NtTib.ExceptionList = OldNtTib->ExceptionList;
    // Xbox XAPI assumes that the thread-local storage is located 
    // at the stack base. (see beginning of function)
    Kpcr.NtTib.StackBase = &Tls[ShimContext.TlsDataSize];
    Kpcr.NtTib.StackLimit = OldNtTib->StackLimit;
    Kpcr.NtTib.ArbitraryUserPointer = (PVOID)GetFS();
    Kpcr.NtTib.Self = &Kpcr.NtTib;

    // Initialize Xbox subsystem part
    Kpcr.SelfPcr = &Kpcr;
    Kpcr.Prcb = &Kpcr.PrcbData;
    Kpcr.Irql = 0;
    Kpcr.Prcb->CurrentThread = (PKTHREAD)&Ethread;
 
    // Allocate LDT entry for new TIB and store selector in old TIB
    AllocateLdtEntry(
        (PWORD)&OldNtTib->ArbitraryUserPointer, (DWORD)&Kpcr, sizeof(KPCR)
    );

    SwapTibs();

    ShimContext.SystemRoutine(ShimContext.StartRoutine, ShimContext.StartContext);

    FatalPrint("ShimCallback: Should never get here.");
    return 0;
}

NTSTATUS Dirtbox::AllocateLdtEntry(PWORD Selector, DWORD Base, DWORD LimitSize)
{
    DWORD Limit = Base + LimitSize;
    LDT_ENTRY LdtEntry;

    EnterCriticalSection(&ThreadingLock);

    // Locate a free LDT entry
    int i;
    for(i = 0; i < MAXIMUM_XBOX_THREADS; i++)
        if(FreeDescriptors[i])
            break;

    if(i == MAXIMUM_XBOX_THREADS)
    {
        LeaveCriticalSection(&ThreadingLock);
        DebugPrint("AllocateLdtEntry: Could not locate free LDT entry.");
        return STATUS_TOO_MANY_THREADS;
    }

    // Set up selector information
    LdtEntry.BaseLow                    = (WORD)(Base & 0xFFFF);
    LdtEntry.HighWord.Bits.BaseMid      = (Base >> 16) & 0xFF;
    LdtEntry.HighWord.Bits.BaseHi       = (Base >> 24) & 0xFF;
    LdtEntry.HighWord.Bits.Type         = 0x13; // RW data segment
    LdtEntry.HighWord.Bits.Dpl          = 3;    // user segment
    LdtEntry.HighWord.Bits.Pres         = 1;    // present
    LdtEntry.HighWord.Bits.Sys          = 0;
    LdtEntry.HighWord.Bits.Reserved_0   = 0;
    LdtEntry.HighWord.Bits.Default_Big  = 1;    // 386 segment
    LdtEntry.HighWord.Bits.Granularity  = 0;    // byte-level granularity

    LdtEntry.LimitLow                   = (WORD)(Limit & 0xFFFF);
    LdtEntry.HighWord.Bits.LimitHi      = (Limit >> 16) & 0xF;

    WORD Sel = ((i + 1) << 3) | 0x7;
    // Allocate selector
    NTSTATUS Res = NtSetLdtEntries(Sel, LdtEntry, 0, 0, 0);
    if(!NT_SUCCESS(Res))
    {
        LeaveCriticalSection(&ThreadingLock);
        DebugPrint("AllocateLdtEntry: Could not set LDT entries.");
        return Res;
    }

    FreeDescriptors[i] = FALSE;
    *Selector = Sel;
    LeaveCriticalSection(&ThreadingLock);

    return STATUS_SUCCESS;
}

NTSTATUS Dirtbox::FreeLdtEntry(WORD Selector)
{
    LDT_ENTRY LdtEntry;

    EnterCriticalSection(&ThreadingLock);

    memset(&LdtEntry, 0, sizeof(LDT_ENTRY));
    NTSTATUS Res = NtSetLdtEntries(Selector, LdtEntry, 0, 0, 0);
    if (!NT_SUCCESS(Res))
    {
        LeaveCriticalSection(&ThreadingLock);
        DebugPrint("FreeLdtEntry: Could not set LDT entries.");
        return Res;
    }
    FreeDescriptors[(Selector >> 3)-1] = TRUE;

    LeaveCriticalSection(&ThreadingLock);

    return STATUS_SUCCESS;
}

// Assumes that we are in Windows TIB
NTSTATUS Dirtbox::FreeTib()
{
    WORD Selector = __readfsword(NT_TIB_USER_POINTER);
    return FreeLdtEntry(Selector);
}