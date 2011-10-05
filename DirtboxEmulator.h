#ifndef _DIRTBOX_EMULATOR_H_
#define _DIRTBOX_EMULATOR_H_

#include "DirtboxDefines.h"
#include "DirtboxTypes.h"

namespace Dirtbox
{
    // DirtboxEmulator.cpp
    typedef VOID (*PMAIN_ROUTINE)();

    VOID __declspec(dllexport) WINAPI Initialize();
    VOID InitializeKernel();
    VOID DebugPrint(PSTR Format, ...);
    VOID FatalPrint(PSTR Format, ...);

    // DirtboxHacks.cpp
    extern HANDLE CurrentDirectory;
    VOID InitializeUsb();
    VOID InitializeDrives();
    VOID InitializeDummyKernel();
    VOID WINAPI InterruptAPC(DWORD_PTR Param);
    BOOLEAN IsValidDosPath(PANSI_STRING String);
    NTSTATUS ConvertObjectAttributes(
        POBJECT_ATTRIBUTES Destination, PUNICODE_STRING ObjectName, PWSTR Buffer, 
        PXBOX_OBJECT_ATTRIBUTES Source
    );

    // DirtboxThreading.cpp
    typedef struct SHIM_CONTEXT
    {
        DWORD TlsDataSize;
        PKSYSTEM_ROUTINE SystemRoutine;
        PKSTART_ROUTINE StartRoutine;
        PVOID StartContext;
    } *PSHIM_CONTEXT;

    VOID InitializeThreading();
    WORD GetFS();
    UINT WINAPI ShimThreadRoutine(PVOID Param);
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
    extern PKINTERRUPT NvInterrupt;
    VOID InitializeGraphics();

    // DirtboxSync.cpp
    HANDLE GetDirtObject(PVOID Object);
}

#endif
