// Exception handler that skips over privileged instructions

#include "Dirtbox.h"

#define _CRT_SECURE_NO_WARNINGS

#define OP_TWO_BYTE 0x0F
#define OP_IN 0xEC
#define OP_OUT 0xEE

#define OP2_WBINVD 0x09

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
