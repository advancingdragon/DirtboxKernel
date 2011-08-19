// Dirtbox GPU emulation source

#include "Dirtbox.h"

using namespace Dirtbox;

DWORD WINAPI Dirtbox::GraphicsThreadCallback(PVOID Parameter)
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
            DEBUG_PRINT("%08x %08x %08x %i\n", RamHtPtr, SemaphoreCtx, GpuTimePtr, *GpuTimePtr);
            *GpuTimePtr = *GpuTimePtr + 1;
        }
        Sleep(100);
    }
    return 0;
}

DWORD Dirtbox::InitializeGraphics()
{
    if (MyVirtualAlloc(TRIGGER_ADDRESS, 0x1000) == NULL)
    {
        DEBUG_PRINT("Error: Could not allocate trigger memory.\n");
        return 1;
    }

    if (MyVirtualAlloc(REGISTER_BASE, 0xA00000) == NULL)
    {
        DEBUG_PRINT("Error: Could not allocate GPU register memory.\n");
        return 1;
    }

    REG32(NV_PFIFO_RUNOUT_STATUS) = 0x10;
    REG32(NV_PFIFO_CACHE1_STATUS) = 0x10;
    REG32(USER_NV_USER_ADDRESS) = REGISTER_BASE + NV_USER;

    CreateThread(NULL, 0, &GraphicsThreadCallback, 0, 0, NULL);

    DEBUG_PRINT("Dirtbox graphics initialized successfully.\n");
    return 0;
}