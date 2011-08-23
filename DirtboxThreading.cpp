#include "Dirtbox.h"
#include "Native.h"

#define MAXIMUM_XBOX_THREADS 15 
#define NT_TIB_SELF 0x18
#define KPCR_SELFPCR 0x1C

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

UINT WINAPI Dirtbox::ShimCallback(PVOID ShimCtxPtr)
{
    SHIM_CONTEXT ShimContext = *(PSHIM_CONTEXT)ShimCtxPtr;
    free(ShimCtxPtr);
    AllocateTib(ShimContext.TlsDataSize);

    SwapTibs();

    ShimContext.SystemRoutine(
        ShimContext.StartRoutine, ShimContext.StartContext
    );

    SwapTibs();

    FreeTib();
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

NTSTATUS Dirtbox::AllocateTib(DWORD TlsDataSize)
{
    // Initialize ETHREAD structure and allocate TLS
    if (TlsDataSize == 0)
    {
        DebugPrint("AllocateTib: TLS must be bigger than zero.");
        return STATUS_INVALID_PARAMETER;
    }
    PVOID Tls = malloc(TlsDataSize);
    if (Tls == NULL)
    {
        DebugPrint("AllocateTib: Could not allocate memory for TLS data.");
        return STATUS_UNSUCCESSFUL;
    }
    memset(Tls, 0, TlsDataSize);

    PETHREAD Ethread = (PETHREAD)malloc(sizeof(ETHREAD));
    if (Ethread == NULL)
    {
        free(Tls);
        DebugPrint("AllocateTib: Could not allocate memory for ETHREAD.");
        return STATUS_UNSUCCESSFUL;
    }
    memset(Ethread, 0, sizeof(ETHREAD));
    Ethread->Tcb.TlsData = Tls;
    Ethread->UniqueThread = (PVOID)GetCurrentThreadId();

    // Initialize Xbox Thread Information Block
    PKPCR Kpcr = (PKPCR)malloc(sizeof(KPCR));
    if (Kpcr == NULL)
    {
        free(Ethread);
        free(Tls);
        DebugPrint("AllocateTib: Could not allocate memory for KPCR.");
        return STATUS_UNSUCCESSFUL;
    }
    memset(Kpcr, 0, sizeof(KPCR));

    // Initialize subsystem independent part
    PNT_TIB OldNtTib;
    WORD OldFs;
    __asm
    {
        mov eax, fs:[NT_TIB_SELF]
        mov OldNtTib, eax
        mov dx, fs
        mov OldFs, dx
    }
    Kpcr->NtTib = *OldNtTib;
    Kpcr->NtTib.ArbitraryUserPointer = (PVOID)OldFs;
    Kpcr->NtTib.Self = &Kpcr->NtTib;
    // Xbox requires the stack base to point to the end of TLS data
    Kpcr->NtTib.StackBase = (PVOID)((DWORD)Tls + TlsDataSize);

    // Initialize Xbox subsystem part
    Kpcr->SelfPcr = Kpcr;
    Kpcr->Prcb = &Kpcr->PrcbData;
    Kpcr->Irql = 0;
    Kpcr->Prcb->CurrentThread = (PKTHREAD)Ethread;

    // Allocate LDT entry for new TIB and store selector in old TIB
    WORD NewFs;
    NTSTATUS Res = AllocateLdtEntry(&NewFs, (DWORD)Kpcr, sizeof(KPCR));
    OldNtTib->ArbitraryUserPointer = (PVOID)NewFs;

    return Res;
}

// Assumes that we are in Windows TIB
NTSTATUS Dirtbox::FreeTib()
{
    PKPCR Kpcr;
    WORD Selector;

    SwapTibs();
    __asm
    {
        mov eax, fs:[KPCR_SELFPCR]
        mov Kpcr, eax
        mov ax, fs
        mov Selector, ax
    }
    SwapTibs();

    free(Kpcr->Prcb->CurrentThread->TlsData);
    free(Kpcr->Prcb->CurrentThread);
    free(Kpcr);
    NTSTATUS Res = FreeLdtEntry(Selector);

    return Res;
}
