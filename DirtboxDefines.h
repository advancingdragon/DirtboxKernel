#ifndef _DIRTBOX_DEFINES_H_
#define _DIRTBOX_DEFINES_H_

#include <windows.h>

#define NT_SUCCESS(Status)           ((NTSTATUS)(Status) >= 0)
#define STATUS_SUCCESS               ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL          ((NTSTATUS)0xC0000001L)
#define STATUS_NOT_IMPLEMENTED       ((NTSTATUS)0xC0000002L)
#define STATUS_INVALID_PARAMETER     ((NTSTATUS)0xC000000DL)
#define STATUS_OBJECT_TYPE_MISMATCH  ((NTSTATUS)0xC0000024L)
#define STATUS_OBJECT_NAME_INVALID   ((NTSTATUS)0xC0000033L)
#define STATUS_TOO_MANY_THREADS      ((NTSTATUS)0xC0000129L)

#define OB_DOS_DEVICES        ((HANDLE)0xFFFFFFFD)

#define PHY32(offset)   (*(PDWORD)(0x80000000 | (offset)))

#define XBE_ENTRY_POINT       (*(PDWORD)0x00010128)
#define XBE_ENTRY_POINT_KEY   0x94859D4B
#define XBE_KERNEL_THUNK      (*(PDWORD)0x00010158)
#define XBE_KERNEL_THUNK_KEY  0xEFB1F152

#define DMA_BASE            0x80000000
#define DUMMY_KERNEL_BASE   0x80010000
#define NEW_NV_BASE         0x84000000
#define NEW_USB_BASE        0x86000000

#define DMA_SIZE            0x00001000
#define NV_SIZE             0x00900000
#define USB_SIZE            0x00001000

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

#define GPU_INST_PAD  0x10000
#define GPU_INST_SIZE 0x5000

#define NV_REG32(offset) (*(PDWORD)(NEW_NV_BASE + (offset)))
//#define GPU_INST_ADDRESS(offset) (NEW_NV_BASE + NV_GPU_INST + GPU_INST_PAD + (offset))

#define NV_METHOD_IS_JUMP(method)   ((method) & 0x00000003)
#define NV_METHOD_INDEX(method)     ((method) & 0x00001FFC)
#define NV_METHOD_SUBCH(method)     (((method) >> 13) & 0x1F)
#define NV_METHOD_COUNT(method)     (((method) >> 18) & 0x7FF)
#define NV_METHOD_IS_JPBH(method)   ((method) & 0x20000000)
#define NV_METHOD_IS_SAME(method)   ((method) & 0x40000000)

#define MAXIMUM_XBOX_THREADS 15 

#define NT_TIB_STACK_BASE 0x04
#define NT_TIB_STACK_LIMIT 0x08
#define NT_TIB_USER_POINTER 0x14
#define NT_TIB_SELF 0x18
#define KPCR_SELF_PCR 0x1C

#define OP_TWO_BYTE 0x0F
#define OP_IN 0xEC
#define OP_OUT 0xEE
#define OP2_WBINVD 0x09

#endif
