// Dirtbox GPU emulation source

#include "DirtboxEmulator.h"
#include <process.h>

namespace Dirtbox
{
    LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo);
    UINT WINAPI GraphicsThreadCallback(PVOID Parameter);

    HANDLE GraphicsThread;
    DWORD PushBuffer;
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
                    ResumeThread(GraphicsThread);
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

UINT WINAPI Dirtbox::GraphicsThreadCallback(PVOID Parameter)
{
    DebugPrint("PushBuffer at 0x%08X", PushBuffer);
    while (TRUE)
    {
        DWORD DmaEnd = NV_REG32(USER_DMA_PUT);
        if (DmaEnd != NV_REG32(USER_DMA_GET))
        {
            DWORD Dma = NV_REG32(USER_DMA_GET);
            while (Dma != DmaEnd)
            {
                DWORD Method = PHY32(Dma);
                Dma += 4;
                if (NV_METHOD_IS_JUMP(Method))
                {
                    Dma = Method & 0x3FFFFFFC;

                    DebugPrint("| JUMP:0x%08X", Dma);
                }
                else if (NV_METHOD_IS_JPBH(Method))
                {
                    // How to calculate?
                    FatalPrint("| JPBH:0x%08X", Method & 0x3FFFFFFC);
                }
                else
                {
                    switch (NV_METHOD_INDEX(Method))
                    {
                    case 0x17C8:
                        break;
                    case 0x17CC:
                        {
                            DWORD Phy = PHY32(Dma + 4) & 0x0EFFFFFF;
                            PNV_VTEST VTest = (PNV_VTEST)(0x80000000 | Phy);
                            VTest->Timestamp = 0;
                            VTest->Result = 10000;
                            VTest->Status = 0;
                        }
                        break;
                    }

                    CHAR Sep = NV_METHOD_IS_SAME(Method) ? '=' : '+';
                    DebugPrint("| METHOD:0x%04X SUBCH:%i", 
                        NV_METHOD_INDEX(Method), NV_METHOD_SUBCH(Method));
                    for (DWORD i = 0; i < NV_METHOD_COUNT(Method); i++)
                    {
                        DebugPrint("| %c  0x%08X", Sep, PHY32(Dma));
                        Dma += 4;
                    }
                }
            }
            NV_REG32(USER_DMA_GET) = NV_REG32(USER_DMA_PUT);
        }
        // the WC cache is flushed
        NV_REG32(NV_PFB_WC_CACHE) = 0;
        Sleep(33); // approx. 30 frames per second (1000/30 == 33)

        /*
        // No longer needed, since BlockOnTime and GpuGetOrNewer are patched.
        if (*(PDWORD)TRIGGER_ADDRESS == 0xDEADBEEF)
        {
            PDWORD RamHtPtr = (PDWORD)GPU_INST_ADDRESS((REG32(NV_PFIFO_RAMHT) & 0xF0) << 8);
            // semaphore
            PDWORD SemaphoreCtx = (PDWORD)GPU_INST_ADDRESS((RamHtPtr[8*2+1] & 0xFFF) << 4);
            PDWORD GpuTimePtr = (PDWORD)((SemaphoreCtx[2] & 0xFFFFFFFC) | 0x80000000);
            DebugPrint("GraphicsThreadCallback: %08x %08x %08x %i", 
                RamHtPtr, SemaphoreCtx, GpuTimePtr, *GpuTimePtr);
            *GpuTimePtr = *GpuTimePtr + 1;
        }
        */
    }
    return 0;
}

VOID Dirtbox::InitializeGraphics()
{
    PVOID Res;
    Res = VirtualAlloc(
        (PVOID)DMA_BASE, DMA_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (Res == NULL)
        FatalPrint("InitializeGraphics: Could not allocate DMA memory.");

    Res = VirtualAlloc(
        (PVOID)NEW_NV_BASE, NEW_NV_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (Res == NULL)
        FatalPrint("InitializeGraphics: Could not allocate GPU register memory.");

    NV_REG32(NV_PFIFO_RUNOUT_STATUS) = 0x10;
    NV_REG32(NV_PFIFO_CACHE1_STATUS) = 0x10;
    NV_REG32(USER_NV_USER_ADDRESS) = NEW_NV_BASE + NV_USER;

    if (AddVectoredExceptionHandler(1, &ExceptionHandler) == NULL)
        FatalPrint("InitializeGraphics: Could not add exception handler.");

    GraphicsThread = (HANDLE)_beginthreadex(
        NULL, 0, &GraphicsThreadCallback, NULL, CREATE_SUSPENDED, NULL
    );
    if (GraphicsThread == 0)
        FatalPrint("InitializeGraphics: Could not create graphics thread, error %i.", errno);

    DebugPrint("InitializeGraphics: Graphics initialized successfully.");
}
