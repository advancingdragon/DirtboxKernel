// Threading - thread local storage and thread information block

#include "DirtboxDefines.h"
#include "DirtboxEmulator.h"
#include "Native.h"

namespace Dirtbox
{
    CRITICAL_SECTION ThreadingLock;
    BOOL FreeDescriptors[MAXIMUM_XBOX_THREADS];

    NTSTATUS AllocateLdtEntry(PWORD Selector, DWORD Base, DWORD LimitSize);
    NTSTATUS FreeLdtEntry(WORD Selector);
    NTSTATUS AllocateTib(PTHREAD_SHIZ ThreadShiz, DWORD TlsDataSize);
}

VOID Dirtbox::InitializeThreading()
{
    InitializeCriticalSection(&ThreadingLock);

    for(int i = 0; i < MAXIMUM_XBOX_THREADS; i++)
        FreeDescriptors[i] = TRUE;

    DebugPrint("InitializeThreading: Threading initialized successfully.");
}

// TODO: Check if expanded stack is big enough to hold THREADING_SHIZ struct.
UINT __declspec(naked) WINAPI Dirtbox::ShimCallback(PVOID ShimCtxPtr)
{
    __asm
    {
        // don't need to save registers, since we'll never
        // return from this function

        // copy contents of ShimContext to nonvolative registers
        mov edx, dword ptr [esp+4]
        mov ebx, dword ptr [edx]SHIM_CONTEXT.TlsDataSize
        mov ebp, dword ptr [edx]SHIM_CONTEXT.SystemRoutine
        mov esi, dword ptr [edx]SHIM_CONTEXT.StartRoutine
        mov edi, dword ptr [edx]SHIM_CONTEXT.StartContext

        // deallocate SHIM_CONTEXT
        push edx
        call dword ptr [free]
        add esp, 4

        // add an additional 4K to the stack
        sub dword ptr fs:[NT_TIB_STACK_BASE], 0x1000
        mov esp, dword ptr fs:[NT_TIB_STACK_BASE]
        // allocate TLS
        sub esp, ebx

        // AllocateTib(TlsDataSize)
        push ebx
        push dword ptr fs:[NT_TIB_STACK_BASE]
        call Dirtbox::AllocateTib
        add esp, 4

        // SwapTibs()
        mov ax, word ptr fs:[NT_TIB_USER_POINTER]
        mov fs, ax

        // SystemRoutine(StartRoutine, StartContext)
        push edi
        push esi
        call ebp

        int 3
    }
}

WORD Dirtbox::GetFS()
{
    __asm
    {
        mov ax, fs
    }
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

NTSTATUS Dirtbox::AllocateTib(PTHREAD_SHIZ ThreadShiz, DWORD TlsDataSize)
{
    memset(ThreadShiz, 0, sizeof(THREAD_SHIZ));

    PNT_TIB OldNtTib = (PNT_TIB)__readfsdword(NT_TIB_SELF);
    // Initialize subsystem independent part
    ThreadShiz->Kpcr.NtTib.ExceptionList = OldNtTib->ExceptionList;
    ThreadShiz->Kpcr.NtTib.StackBase = OldNtTib->StackBase;
    ThreadShiz->Kpcr.NtTib.StackLimit = OldNtTib->StackLimit;
    ThreadShiz->Kpcr.NtTib.ArbitraryUserPointer = (PVOID)GetFS();
    ThreadShiz->Kpcr.NtTib.Self = &ThreadShiz->Kpcr.NtTib;

    // Initialize Xbox subsystem part
    ThreadShiz->Kpcr.SelfPcr = &ThreadShiz->Kpcr;
    ThreadShiz->Kpcr.Prcb = &ThreadShiz->Kpcr.PrcbData;
    ThreadShiz->Kpcr.Irql = 0;
    ThreadShiz->Kpcr.Prcb->CurrentThread = (PKTHREAD)&ThreadShiz->Ethread;

    // Initialize Ethread structure
    ThreadShiz->Ethread.Tcb.TlsData = (PVOID)((DWORD)OldNtTib->StackBase - TlsDataSize);
    ThreadShiz->Ethread.UniqueThread = (PVOID)GetCurrentThreadId();

    // Allocate LDT entry for new TIB and store selector in old TIB
    WORD NewFs;
    NTSTATUS Res = AllocateLdtEntry(&NewFs, (DWORD)&ThreadShiz->Kpcr, sizeof(KPCR));
    OldNtTib->ArbitraryUserPointer = (PVOID)NewFs;

    // Restore NT stack base
    OldNtTib->StackBase = (PVOID)((DWORD)OldNtTib->StackBase + 0x1000);

    return Res;
}

// Assumes that we are in Windows TIB
NTSTATUS Dirtbox::FreeTib()
{
    WORD Selector = __readfsword(NT_TIB_USER_POINTER);
    return FreeLdtEntry(Selector);
}