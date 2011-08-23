// Dirtbox GPU emulation source

#include "Dirtbox.h"
#include <process.h>

namespace Dirtbox
{
    UINT WINAPI GraphicsThreadCallback(PVOID Parameter);
}

UINT WINAPI Dirtbox::GraphicsThreadCallback(PVOID Parameter)
{
    while (TRUE)
    {
        REG32(NV_PFB_WC_CACHE) = 0;
        REG32(USER_DMA_GET) = REG32(USER_DMA_PUT);
        if (*(DWORD *)TRIGGER_ADDRESS == 0xDEADBEEF)
        {
            DWORD *RamHtPtr = (DWORD *)GPU_INST_ADDRESS((REG32(NV_PFIFO_RAMHT) & 0xF0) << 8);
            // semaphore
            DWORD *SemaphoreCtx = (DWORD *)GPU_INST_ADDRESS((RamHtPtr[8*2+1] & 0xFFF) << 4);
            DWORD *GpuTimePtr = (DWORD *)((SemaphoreCtx[2] & 0xFFFFFFFC) | 0x80000000);
            DebugPrint("GraphicsThreadCallback: %08x %08x %08x %i", 
                RamHtPtr, SemaphoreCtx, GpuTimePtr, *GpuTimePtr);
            *GpuTimePtr = *GpuTimePtr + 1;
        }
        Sleep(100);
    }
    return 0;
}

VOID Dirtbox::InitializeGraphics()
{
    PVOID Res;
    Res = VirtualAlloc(
        (PVOID)TRIGGER_ADDRESS, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (Res == NULL)
        FatalPrint("InitializeGraphics: Could not allocate trigger memory.");

    Res = VirtualAlloc(
        (PVOID)REGISTER_BASE, 0xA00000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (Res == NULL)
        FatalPrint("InitializeGraphics: Could not allocate GPU register memory.");

    REG32(NV_PFIFO_RUNOUT_STATUS) = 0x10;
    REG32(NV_PFIFO_CACHE1_STATUS) = 0x10;
    REG32(USER_NV_USER_ADDRESS) = REGISTER_BASE + NV_USER;

    HANDLE Thr = (HANDLE)_beginthreadex(NULL, 0, &GraphicsThreadCallback, 0, 0, NULL);
    if (!VALID_HANDLE(Thr))
        FatalPrint("InitializeGraphics: Could not create graphics thread.");

    DebugPrint("InitializeGraphics: Graphics initialized successfully.");
}