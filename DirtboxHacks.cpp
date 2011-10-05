// Miscellaneous hacks

#include "DirtboxEmulator.h"
#include "Native.h"

namespace Dirtbox
{
    typedef struct DUMMY_KERNEL
    {
        IMAGE_DOS_HEADER DosHeader;
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_SECTION_HEADER SectionHeader;
    } *PDUMMY_KERNEL;

    HANDLE CurrentDirectory = NULL;
}

VOID Dirtbox::InitializeUsb()
{
    PVOID UsbRegisters = VirtualAlloc(
        (PVOID)NEW_USB_BASE, USB_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (UsbRegisters == NULL)
        FatalPrint("InitializeUsb: Could not allocate USB registers.");
    memset(UsbRegisters, 0, USB_SIZE);

    DebugPrint("InitializeUsb: USB registers initialized successfully.");
}

VOID Dirtbox::InitializeDrives()
{
    CHAR CurrentPath[MAX_PATH];

    GetCurrentDirectoryA(MAX_PATH, CurrentPath);
    CurrentDirectory = CreateFileA(
        CurrentPath, GENERIC_READ, FILE_SHARE_READ, NULL, 
        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL
    );
    if (CurrentDirectory == INVALID_HANDLE_VALUE)
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

// this is needed to satisfy XapiRestrictCodeSelectorLimit in the runtime.
VOID Dirtbox::InitializeDummyKernel()
{
    PDUMMY_KERNEL DummyKernel = (PDUMMY_KERNEL)VirtualAlloc(
        (PVOID)DUMMY_KERNEL_BASE, sizeof(DUMMY_KERNEL), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (DummyKernel == NULL)
        FatalPrint("InitializeDummyKernel: Could not allocate dummy kernel.");
    memset(DummyKernel, 0, sizeof(DUMMY_KERNEL));

    // XapiRestrictCodeSelectorLimit only checks these fields.
    DummyKernel->DosHeader.e_lfanew = sizeof(IMAGE_DOS_HEADER); // RVA of NtHeaders
    DummyKernel->FileHeader.SizeOfOptionalHeader = 0;
    DummyKernel->FileHeader.NumberOfSections = 1;
    // as long as this doesn't start with "INIT"
    strncpy_s((PSTR)DummyKernel->SectionHeader.Name, 8, "DONGS", 8);

    DebugPrint("InitializeDummyKernel: Dummy kernel initialized successfully.");
}

VOID WINAPI Dirtbox::InterruptAPC(DWORD_PTR Param)
{
    // at first we are in NT TIB
    DebugPrint("InterruptAPC: 0x%08x", Param);

    SwapTibs();

    PKINTERRUPT Interrupt = (PKINTERRUPT)Param;
    Interrupt->ServiceRoutine(Interrupt, Interrupt->ServiceContext);

    SwapTibs();
}

BOOLEAN Dirtbox::IsValidDosPath(PANSI_STRING String)
{
    return String->Length >= 3 &&
        strpbrk(String->Buffer, "CDTUZcdtuz") == String->Buffer &&
        strncmp(String->Buffer + 1, ":\\", 2) == 0;
}

NTSTATUS Dirtbox::ConvertObjectAttributes(
    POBJECT_ATTRIBUTES Destination, PUNICODE_STRING ObjectName, PWSTR Buffer, 
    PXBOX_OBJECT_ATTRIBUTES Source
)
{
    if (Source->RootDirectory == OB_DOS_DEVICES)
    {
        // validate correctness of path
        if (!IsValidDosPath(Source->ObjectName))
        {
            DebugPrint("ConvertObjectAttributes: Invalid path name.");
            return STATUS_OBJECT_NAME_INVALID;
        }

        // build the new path
        RtlInitEmptyUnicodeString(ObjectName, Buffer, MAX_PATH);
        RtlAnsiStringToUnicodeString(ObjectName, Source->ObjectName, FALSE);

        // ':' is not an allowed char in names, so replace it with _
        ObjectName->Buffer[1] = L'_';
    }
    else if (Source->RootDirectory == NULL)
    {
        // build the new path
        RtlInitEmptyUnicodeString(ObjectName, Buffer, MAX_PATH);
        RtlAppendUnicodeToString(ObjectName, L"Dummy");
    }
    else
    {
        DebugPrint("ConvertObjectAttributes: Invalid root directory.");
        return STATUS_UNSUCCESSFUL;
    }

    // Convert XBOX_OBJECT_ATTRIBUTES to Windows NT OBJECT_ATTRIBUTES
    Destination->Length = sizeof(OBJECT_ATTRIBUTES);
    Destination->ObjectName = ObjectName;
    Destination->Attributes = Source->Attributes;
    Destination->RootDirectory = CurrentDirectory;
    Destination->SecurityDescriptor = NULL;
    Destination->SecurityQualityOfService = NULL;

    return STATUS_SUCCESS;
}
