// Miscellaneous hacks

#include "Dirtbox.h"
#include "Native.h"

#define OP_TWO_BYTE 0x0F
#define OP_IN 0xEC
#define OP_OUT 0xEE

#define OP2_WBINVD 0x09

namespace Dirtbox
{
    typedef struct DUMMY_KERNEL
    {
        IMAGE_DOS_HEADER DosHeader;
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_SECTION_HEADER SectionHeader;
    } *PDUMMY_KERNEL;

    HANDLE CurrentDirectory;

    LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo);
}

// Exception handler that skips over privileged instructions
LONG WINAPI Dirtbox::ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    PEXCEPTION_RECORD Except = ExceptionInfo->ExceptionRecord;
    PCONTEXT Context = ExceptionInfo->ContextRecord;

    switch (Except->ExceptionCode)
    {
    case EXCEPTION_PRIV_INSTRUCTION:
        {
            // The only privileged instructions that we encounter here are
            // in, out, and wbinvd.
            BYTE Opcode = *(BYTE *)Context->Eip;
            Context->Eip += 1;

            switch (Opcode)
            {
            case OP_TWO_BYTE:
                Opcode = *(BYTE *)Context->Eip;
                Context->Eip += 1;
                if (Opcode == OP2_WBINVD)
                    break;
                else
                    return EXCEPTION_CONTINUE_SEARCH;
                break;
            case OP_IN:
                Context->Eax &= 0xFFFFFF00;
                break;
            case OP_OUT:
                break;
            default:
                return EXCEPTION_CONTINUE_SEARCH;
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }

    default:
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

VOID Dirtbox::InitializeException()
{
    if (AddVectoredExceptionHandler(1, &ExceptionHandler) == NULL)
        FatalPrint("InitializeException: Could not add exception handler.");

    DebugPrint("InitializeException: Exception handler added successfully.");
}

// this is needed to satisfy XapiRestrictCodeSelectorLimit in the runtime.
VOID Dirtbox::InitializeDummyKernel()
{
    PDUMMY_KERNEL DummyKernel = (PDUMMY_KERNEL)VirtualAlloc(
        (PVOID)DUMMY_KERNEL_ADDRESS, sizeof(DUMMY_KERNEL), 
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (DummyKernel == NULL)
        FatalPrint("InitializeDummyKernel: Could not turn allocate dummy kernel.");
    memset(DummyKernel, 0, sizeof(DUMMY_KERNEL));

    // XapiRestrictCodeSelectorLimit only checks these fields.
    DummyKernel->DosHeader.e_lfanew = sizeof(IMAGE_DOS_HEADER); // RVA of NtHeaders
    DummyKernel->FileHeader.SizeOfOptionalHeader = 0;
    DummyKernel->FileHeader.NumberOfSections = 1;
    // as long as this doesn't start with "INIT"
    strncpy_s((PSTR)DummyKernel->SectionHeader.Name, 8, "DONGS", 8);

    DebugPrint("InitializeDummyKernel: Dummy kernel initialized successfully.");
}

VOID Dirtbox::InitializeDrives()
{
    CHAR CurrentPath[MAX_PATH];

    GetCurrentDirectoryA(MAX_PATH, CurrentPath);
    CurrentDirectory = CreateFileA(
        CurrentPath, GENERIC_READ, FILE_SHARE_READ, NULL, 
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL
    );
    if (!VALID_HANDLE(CurrentDirectory))
        FatalPrint("InitializeDrives: Could not open current directory.");

    // Xbox partitions
    CreateDirectoryA("C_", NULL);
    CreateDirectoryA("D_", NULL);
    CreateDirectoryA("T_", NULL);
    CreateDirectoryA("U_", NULL);
    CreateDirectoryA("Z_", NULL);
    // Dummy folder for volume openings.
    CreateDirectoryA("Dummy", NULL);

    DebugPrint("InitializeDrives: Virtual drives initialized successfully.");
}