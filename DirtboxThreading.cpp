#include "Dirtbox.h"
#include "Native.h"

#define _CRT_SECURE_NO_WARNINGS

#define MAXIMUM_XBOX_THREADS 15 

static CRITICAL_SECTION ThreadingLock;
static BOOL FreeDescriptors[MAXIMUM_XBOX_THREADS];

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

VOID Dirtbox::AllocateTib()
{
    WORD OldFs;
    WORD NewFs;
    PNT_TIB OldNtTib;

    __asm
    {
        mov ax, fs
        mov OldFs, ax

        mov eax, fs:[0x18]
        mov OldNtTib, eax
    }

    // Allocate LDT entry
    XBOX_TIB *XboxTib = (XBOX_TIB *)malloc(sizeof(XBOX_TIB));
    memset((PVOID)XboxTib, 0, sizeof(XBOX_TIB));

    memcpy((PVOID)&XboxTib->NtTib, (PVOID)OldNtTib, sizeof(NT_TIB));
    XboxTib->NtTib.ArbitraryUserPointer = (PVOID)OldFs;
    XboxTib->NtTib.Self = &XboxTib->NtTib;

    XboxTib->Self = XboxTib;
    XboxTib->Prcb = &XboxTib->PrcbData;
    XboxTib->Irql = 0;

    NewFs = Dirtbox::AllocateLdtEntry((DWORD)XboxTib, (DWORD)XboxTib + sizeof(XBOX_TIB));

    __asm
    {
        mov ax, NewFs
        mov fs:[0x14], ax
    }
}

// Assumes that we are in Windows TIB
VOID Dirtbox::FreeTib()
{
    XBOX_TIB *XboxTib;
    WORD Selector;

    SwapTibs();
    __asm
    {
        mov eax, fs:[0x1C]
        mov XboxTib, eax
        mov ax, fs
        mov Selector, ax
    }
    SwapTibs();

    free((PVOID)XboxTib);
    FreeLdtEntry(Selector);
}
