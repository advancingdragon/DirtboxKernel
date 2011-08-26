#ifndef _DIRTBOX_EMULATOR_H_
#define _DIRTBOX_EMULATOR_H_

#include "DirtboxTypes.h"

namespace Dirtbox
{
    // DirtboxEmulator.cpp
    typedef VOID (*PMAIN_ROUTINE)();

    VOID __declspec(dllexport) WINAPI Initialize();
    VOID DebugPrint(PSTR Format, ...);
    VOID FatalPrint(PSTR Format, ...);

    // DirtboxHacks.cpp
    extern HANDLE CurrentDirectory;

    VOID InitializeException();
    VOID InitializeDummyKernel();
    VOID InitializeDrives();

    // DirtboxThreading.cpp
    typedef struct SHIM_CONTEXT
    {
        DWORD TlsDataSize;
        PKSYSTEM_ROUTINE SystemRoutine;
        PKSTART_ROUTINE StartRoutine;
        PVOID StartContext;
    } *PSHIM_CONTEXT;

    typedef struct THREAD_SHIZ
    {
        FX_SAVE_AREA FxSaveArea;
        KPCR Kpcr;
        ETHREAD Ethread;
    } *PTHREAD_SHIZ;

    VOID InitializeThreading();
    UINT WINAPI ShimCallback(PVOID ShimCtxPtr);
    WORD GetFS();
    NTSTATUS FreeTib();
    static inline VOID SwapTibs()
    {
        __asm
        {
            mov ax, word ptr fs:[NT_TIB_USER_POINTER]
            mov fs, ax
        }
    }

    // DirtboxGraphics.cpp
    VOID InitializeGraphics();
}

#endif
