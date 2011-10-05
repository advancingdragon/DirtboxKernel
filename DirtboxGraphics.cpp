// Dirtbox GPU emulation source

#include "DirtboxEmulator.h"
#include <process.h>

namespace Dirtbox
{
    PKINTERRUPT NvInterrupt = NULL;
    HANDLE NvTimer = NULL;
    DWORD PushBuffer = 0;

    LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo);
    VOID CDECL NvThreadRoutine(PVOID Param);
    VOID ExecuteNvMethods();
}

VOID Dirtbox::InitializeGraphics()
{
    PVOID Res;
    Res = VirtualAlloc((PVOID)DMA_BASE, DMA_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (Res == NULL)
        FatalPrint("InitializeGraphics: Could not allocate DMA memory.");

    Res = VirtualAlloc((PVOID)NEW_NV_BASE, NV_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (Res == NULL)
        FatalPrint("InitializeGraphics: Could not allocate GPU register memory.");

    NV_REG32(NV_PFIFO_RUNOUT_STATUS) = 0x10;
    NV_REG32(NV_PFIFO_CACHE1_STATUS) = 0x10;
    NV_REG32(USER_NV_USER_ADDRESS) = NEW_NV_BASE + NV_USER;

    if (AddVectoredExceptionHandler(1, &ExceptionHandler) == NULL)
        FatalPrint("InitializeGraphics: Could not add VEH handler; %i.", GetLastError());

    DebugPrint("InitializeGraphics: Graphics initialized successfully.");
}

// Skips over privileged instructions: in, out, and wbinvd.
LONG WINAPI Dirtbox::ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    PEXCEPTION_RECORD Except = ExceptionInfo->ExceptionRecord;
    PCONTEXT Context = ExceptionInfo->ContextRecord;

    switch (Except->ExceptionCode)
    {
    case EXCEPTION_PRIV_INSTRUCTION:
        {
            BYTE Opcode = *(PBYTE)Context->Eip;
            Context->Eip++;

            switch (Opcode)
            {
            case OP_TWO_BYTE:
                Opcode = *(PBYTE)Context->Eip;
                Context->Eip++;
                // wbinvd follows right after pushbuffer address is given to DMA
                if (Opcode == OP2_WBINVD)
                {
                    PushBuffer = *(PDWORD)DMA_BASE & 0xFFFFFFFE;
                    NV_REG32(USER_DMA_PUT) = PushBuffer;
                    NV_REG32(USER_DMA_GET) = PushBuffer;
                    // wbinvd triggers starting of the GPU thread
                    if (_beginthread(&NvThreadRoutine, 0, NULL) == -1L)
                        return EXCEPTION_CONTINUE_SEARCH;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
                Context->Eip--;
                break;
            case OP_IN:
                Context->Eax &= 0xFFFFFF00;
                return EXCEPTION_CONTINUE_EXECUTION;
            case OP_OUT:
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            Context->Eip--;
            return EXCEPTION_CONTINUE_SEARCH;
        }

    default:
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

VOID CDECL Dirtbox::NvThreadRoutine(PVOID Param)
{
    DebugPrint("NvThreadRoutine: Started GPU thread.");
    NvTimer = CreateWaitableTimerA(NULL, FALSE, "Dirtbox_NvTimer");
    if (NvTimer == NULL)
        FatalPrint("NvThreadRoutine: Could not create GPU timer; %i.", GetLastError());
    LARGE_INTEGER DueTime;
    DueTime.QuadPart = 0;
    if (!SetWaitableTimer(NvTimer, &DueTime, 1000/50, NULL, NULL, FALSE))
        FatalPrint("NvThreadRoutine: Could not set GPU timer; %i.", GetLastError());

    while (TRUE)
    {
        // execute GPU methods twice as fast as the VBlank (25 FPS)
        WaitForSingleObject(NvTimer, INFINITE);
        ExecuteNvMethods();
        WaitForSingleObject(NvTimer, INFINITE);
        // call VBlank interrupt
        PKINTERRUPT NvInterrupt_ = NvInterrupt;
        if (NvInterrupt_ != NULL)
        {
            HANDLE Thread = (HANDLE)NvInterrupt_->DispatchCode[21];
            if (QueueUserAPC(&InterruptAPC, Thread, (DWORD_PTR)NvInterrupt_) == 0)
                FatalPrint("NvThreadRoutine: Could not queue APC; %i.", GetLastError());
        }
        ExecuteNvMethods();
    }
}

// There's a lot of GPU registers that don't have to be keep written to 
// because the busyloops are already patched.
VOID Dirtbox::ExecuteNvMethods()
{
    // USER_DMA_PUT must be read only once at the beginning of this 
    // routine, since it may be modified by other thread at any time. If 
    // read more than once, it may change, thus causing a race condition.
    DWORD DmaPut = NV_REG32(USER_DMA_PUT);
    DWORD DmaGet = NV_REG32(USER_DMA_GET);
    while (DmaGet != DmaPut)
    {
        DWORD Method = PHY32(DmaGet);
        DmaGet += 4;
        if (NV_METHOD_IS_JUMP(Method))
        {
            DebugPrint("| JUMP:0x%08X", Method & 0x3FFFFFFC);

            DmaGet = Method & 0x3FFFFFFC;
        }
        else if (NV_METHOD_IS_JPBH(Method))
        {
            // How to calculate?
            FatalPrint("| JPBH:0x%08X", Method & 0x3FFFFFFC);
        }
        else
        {
            CHAR Sep = NV_METHOD_IS_SAME(Method) ? '=' : '+';
            DebugPrint("| METHOD:0x%04X SUBCH:%i", 
                NV_METHOD_INDEX(Method), NV_METHOD_SUBCH(Method));

            switch (NV_METHOD_INDEX(Method))
            {
            case 0x17C8: // visibility test start
                break;
            case 0x17CC: // visibility test end
                {
                    DWORD Phy = PHY32(DmaGet + 4) & 0x0EFFFFFF;
                    PNV_VTEST VTest = (PNV_VTEST)(0x80000000 | Phy);
                    VTest->Timestamp = 0;
                    VTest->Result = 10000;
                    VTest->Status = 0;
                }
                break;
            }

            for (DWORD i = 0; i < NV_METHOD_COUNT(Method); i++)
            {
                DebugPrint("| %c  0x%08X", Sep, PHY32(DmaGet));
                DmaGet += 4;
            }
        }
    }
    NV_REG32(USER_DMA_GET) = DmaGet;
}
