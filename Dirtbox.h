#ifndef DIRTBOX_KERNEL_H
#define DIRTBOX_KERNEL_H

#include "DirtboxTypes.h"
#include <stdio.h>

#define EXPORT __declspec(dllexport)

#define TRIGGER_ADDRESS     0x80000000
#define REGISTER_BASE       0x84000000

#define NV_PFIFO_RAMHT          0x002210
#define NV_PFIFO_RAMFC          0x002214
#define NV_PFIFO_RUNOUT_STATUS  0x002400
#define NV_PFIFO_CACHE1_STATUS  0x003214
#define NV_PFB_WC_CACHE         0x100410
#define NV_GPU_INST             0x700000
#define NV_USER                 0x800000
#define USER_DMA_PUT            0x800040
#define USER_DMA_GET            0x800044
#define USER_NV_USER_ADDRESS    0x801C20

#define PADDING_SIZE  0x10000
#define GPU_INST_SIZE 0x5000

#define REG32(offset) (*(DWORD *)(REGISTER_BASE + (offset)))
#define GPU_INST_ADDRESS(offset) (REGISTER_BASE + NV_GPU_INST + PADDING_SIZE + (offset))

#define KERNEL_IMAGE_THUNK_ADDR     0x00010158
#define DEBUG_KEY                   0xEFB1F152

#define DEBUG_PRINT(str, ...) \
    do \
    { \
        printf(str, __VA_ARGS__); \
        fflush(stdout); \
    } while (0)

namespace Dirtbox
{
    static inline DWORD MyVirtualAlloc(DWORD Address, DWORD Size)
    {
        return (DWORD)VirtualAlloc(
            (LPVOID)Address, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
        );
    }

    LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo);

    static inline void SwapTibs()
    {
        __asm
        {
            mov ax, fs:[0x14]
            mov fs, ax
        }
    }
    VOID InitializeThreading();
    WORD AllocateLdtEntry(DWORD Base, DWORD Limit);
    VOID FreeLdtEntry(DWORD Selector);
    VOID AllocateTib();
    VOID FreeTib();

    DWORD GraphicsThread(LPVOID Parameter);
    DWORD InitializeGraphics();

    VOID EXPORT WINAPI _Initialize();

    LPVOID EXPORT NTAPI AvGetSavedDataAddress();
    VOID EXPORT NTAPI AvSendTVEncoderOption(
        LPVOID RegisterBase, DWORD Option, DWORD Param, LPDWORD Result
    );
    DWORD EXPORT NTAPI AvSetDisplayMode(
        LPVOID RegisterBase, DWORD Step, DWORD Mode, DWORD Format, 
        DWORD Pitch, DWORD FrameBuffer
    );
    VOID EXPORT NTAPI AvSetSavedDataAddress(
        LPVOID Address
    );
    NTSTATUS EXPORT NTAPI DbgPrint(
        LPSTR Output
    );
    DWORD EXPORT NTAPI HalGetInterruptVector(
        DWORD BusInterruptLevel, PKIRQL Irql
    );
    VOID EXPORT NTAPI HalReadWritePCISpace(
        DWORD BusNumber, DWORD SlotNumber, DWORD RegisterNumber, LPVOID Buffer, 
        DWORD Length, BOOLEAN WritePCISpace
    );
    VOID EXPORT NTAPI HalRegisterShutdownNotification(
        PHAL_SHUTDOWN_REGISTRATION ShutdownRegistration, CHAR Register
    );
    BOOLEAN EXPORT NTAPI KeConnectInterrupt(
        PKINTERRUPT Interrupt
    );
    BOOLEAN EXPORT NTAPI KeDisconnectInterrupt(
        PKINTERRUPT Interrupt
    );
    VOID EXPORT NTAPI KeInitializeDpc(
        PKDPC Dpc, PKDEFERRED_ROUTINE DeferredRoutine, LPVOID DeferredContext
    );
    VOID EXPORT NTAPI KeInitializeInterrupt(
        PKINTERRUPT Interrupt, PKSERVICE_ROUTINE ServiceRoutine, LPVOID ServiceContext, DWORD Vector,
        KIRQL Irql, KINTERRUPT_MODE InterruptMode, BOOLEAN ShareVector
    );
    BOOLEAN EXPORT NTAPI KeInsertQueueDpc(
        PKDPC Dpc, LPVOID SystemArgument1, LPVOID SystemArgument2
    );
    LONG EXPORT NTAPI KeSetEvent(
        PKEVENT Event, LONG Increment, CHAR Wait
    );
    LONG EXPORT NTAPI KeWaitForSingleObject(
        LPVOID Object, KWAIT_REASON WaitReason, CHAR WaitMode, CHAR Alertable, 
        PLARGE_INTEGER Timeout
    );
    LPVOID EXPORT NTAPI MmClaimGpuInstanceMemory(
        DWORD NumberOfBytes, LPDWORD NumberOfPaddingBytes
    );
    VOID EXPORT NTAPI MmFreeContiguousMemory(
        LPVOID BaseAddress
    );
    VOID EXPORT NTAPI MmPersistContiguousMemory(
        LPVOID BaseAddress, DWORD NumberOfBytes, BOOLEAN Persist
    );
    DWORD EXPORT NTAPI MmQueryAllocationSize(
        LPVOID BaseAddress
    );
    NTSTATUS EXPORT NTAPI NtClose(
        HANDLE Handle
    );
    NTSTATUS EXPORT NTAPI NtCreateFile(
        PHANDLE FileHandle, DWORD DesiredAccess, LPVOID ObjectAttributes, LPVOID IoStatusBlock,
        PLARGE_INTEGER AllocationSize, DWORD FileAttributes, DWORD ShareAccess, DWORD CreateDisposition, 
        DWORD CreateOptions 
    );
    NTSTATUS EXPORT NTAPI NtReadFile(
        HANDLE FileHandle, HANDLE Event, LPVOID ApcRoutine, LPVOID ApcContext,
        LPVOID IoStatusBlock, LPVOID Buffer, DWORD Length, PLARGE_INTEGER ByteOffset
    );
    NTSTATUS EXPORT NTAPI NtSetInformationFile(
        HANDLE FileHandle, LPVOID IoStatusBlock, LPVOID FileInformation, DWORD Length, 
        DWORD FileInformationClass
    );
    NTSTATUS EXPORT NTAPI NtWriteFile( 
        HANDLE FileHandle, LPVOID Event, LPVOID ApcRoutine, LPVOID ApcContext,
        LPVOID IoStatusBlock, LPVOID Buffer, DWORD Length, PLARGE_INTEGER ByteOffset
    );
    extern XBOX_HARDWARE_INFO EXPORT XboxHardwareInfo;
}

#endif
