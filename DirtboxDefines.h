#ifndef _DIRTBOX_DEFINES_H_
#define _DIRTBOX_DEFINES_H_

#include <windows.h>

#define NT_SUCCESS(Status)           ((NTSTATUS)(Status) >= 0)
#define STATUS_SUCCESS               ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL          ((NTSTATUS)0xC0000001L)
#define STATUS_NOT_IMPLEMENTED       ((NTSTATUS)0xC0000002L)
#define STATUS_INVALID_PARAMETER     ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_NAME_INVALID   ((NTSTATUS)0xC0000033L)
#define STATUS_TOO_MANY_THREADS      ((NTSTATUS)0xC0000129L)

// warning, double using macro
#define VALID_HANDLE(Handle)  ((Handle) != NULL && (Handle) != INVALID_HANDLE_VALUE)
#define OB_DOS_DEVICES        ((HANDLE) 0xFFFFFFFD)

#define XBE_ENTRY_POINT       (*(PDWORD)0x00010128)
#define XBE_ENTRY_POINT_KEY   0x94859D4B
#define XBE_KERNEL_THUNK      (*(PDWORD)0x00010158)
#define XBE_KERNEL_THUNK_KEY  0xEFB1F152

#define TRIGGER_ADDRESS       0x80000000
#define DUMMY_KERNEL_ADDRESS  0x80010000
#define REGISTER_BASE         0x84000000

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

#define REG32(offset) (*(PDWORD)(REGISTER_BASE + (offset)))
#define GPU_INST_ADDRESS(offset) (REGISTER_BASE + NV_GPU_INST + PADDING_SIZE + (offset))

#define MAXIMUM_XBOX_THREADS 15 

#define NT_TIB_STACK_BASE 0x04
#define NT_TIB_STACK_LIMIT 0x08
#define NT_TIB_USER_POINTER 0x14
#define NT_TIB_SELF 0x18

#endif
