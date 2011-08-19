#include "Dirtbox.h"
#include "Native.h"

#define MAXIMUM_XBOX_THREADS 15 
#define NT_TIB_SELF 0x18
#define KPCR_SELFPCR 0x1C

using namespace Dirtbox;

static CRITICAL_SECTION ThreadingLock;
static BOOL FreeDescriptors[MAXIMUM_XBOX_THREADS];

DWORD WINAPI Dirtbox::ShimCallback(PVOID Parameter)
{
    PSHIM_CONTEXT ShimContext = (PSHIM_CONTEXT)Parameter;
    AllocateTib(ShimContext->TlsDataSize);
    SwapTibs();

    ShimContext->SystemRoutine(
        ShimContext->StartRoutine, ShimContext->StartRoutine
    );

    SwapTibs();
    FreeTib();
    free(ShimContext);
    return 0;
}

VOID Dirtbox::InitializeThreading()
{
    InitializeCriticalSection(&ThreadingLock);

    for(int i = 0; i < MAXIMUM_XBOX_THREADS; i++)
        FreeDescriptors[i] = TRUE;
}

WORD Dirtbox::AllocateLdtEntry(DWORD Base, DWORD Limit)
{
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
		DEBUG_PRINT("Could not locate free LDT entry (too many threads?)");
        return 1;
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

    WORD Selector = ((i + 1) << 3) | 0x7;
    // Allocate selector
    if(NtSetLdtEntries(Selector, LdtEntry, 0, 0, 0) != 0)
    {
        LeaveCriticalSection(&ThreadingLock);
        DEBUG_PRINT("Could not set LDT entries");
        return 1;
    }

    FreeDescriptors[i] = FALSE;
    LeaveCriticalSection(&ThreadingLock);

    return Selector;
}

VOID Dirtbox::FreeLdtEntry(WORD Selector)
{
    LDT_ENTRY LdtEntry;

    EnterCriticalSection(&ThreadingLock);

    ZeroMemory(&LdtEntry, sizeof(LDT_ENTRY));
    NtSetLdtEntries(Selector, LdtEntry, 0, 0, 0);
    FreeDescriptors[(Selector >> 3)-1] = TRUE;

    LeaveCriticalSection(&ThreadingLock);
}

VOID Dirtbox::AllocateTib(DWORD TlsDataSize)
{
    WORD OldFs;
    WORD NewFs;
    PNT_TIB OldNtTib;

    __asm
    {
        mov ax, fs
        mov OldFs, ax

        mov eax, fs:[NT_TIB_SELF]
        mov OldNtTib, eax
    }

    // Initialize Xbox Thread Information Block
    PKPCR Kpcr = (PKPCR)malloc(sizeof(KPCR));
    memset(Kpcr, 0, sizeof(KPCR));

    // Initialize subsystem independent part
    memcpy(&Kpcr->NtTib, OldNtTib, sizeof(NT_TIB));
    Kpcr->NtTib.ArbitraryUserPointer = (PVOID)OldFs;
    Kpcr->NtTib.Self = &Kpcr->NtTib;

    // Initialize Xbox subsystem part
    Kpcr->SelfPcr = Kpcr;
    Kpcr->Prcb = &Kpcr->PrcbData;
    Kpcr->Irql = 0;

    // Initialize ETHREAD structure and allocate TLS
    PETHREAD Ethread = (PETHREAD)malloc(sizeof(ETHREAD));
    memset(Ethread, 0, sizeof(ETHREAD));
    if (TlsDataSize != 0)
    {
        Ethread->Tcb.TlsData = malloc(TlsDataSize);
    }
    Ethread->UniqueThread = (PVOID)GetCurrentThreadId();
    Kpcr->Prcb->CurrentThread = (PKTHREAD)Ethread;

    NewFs = AllocateLdtEntry((DWORD)Kpcr, (DWORD)Kpcr + sizeof(KPCR));

    OldNtTib->ArbitraryUserPointer = (PVOID)NewFs;
}

// Assumes that we are in Windows TIB
VOID Dirtbox::FreeTib()
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

    if (Kpcr->Prcb->CurrentThread->TlsData != NULL)
        free(Kpcr->Prcb->CurrentThread->TlsData);
    free(Kpcr->Prcb->CurrentThread);
    free(Kpcr);
    FreeLdtEntry(Selector);
}
