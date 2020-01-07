/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2017-2019 Cyberhaven
/// Copyright (c) 2013 Dependable Systems Lab, EPFL
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef _S2E_WINDOWS_H_

#define _S2E_WINDOWS_H_

#if defined(USER_APP)
#include <windows.h>
#include <stdio.h>
#ifndef NTSTATUS
#define NTSTATUS     ULONG
#define DbgPrint printf
#endif
#else
#include <ntddk.h>
#include <Ntstrsafe.h>
#endif

#pragma warning(push)
#pragma warning(disable: 26477) // We can't use nullptr here because the header can be used from C
#pragma warning(disable: 26494) // Uninited variable, caused by va_list
#pragma warning(disable: 26485) // Array to pointer decay in various vprintf functions
#pragma warning(disable: 26486) // Complains about passing ap to vprintf functions

/** Use these to validate the size of the structures at compile time */
#define _x_CCASSERT_LINE_CAT(predicate, line) \
    typedef char constraint_violated_on_line_##line[2*((predicate)!=0)-1]

#define CCASSERT(predicate) _x_CCASSERT_LINE_CAT(predicate, __LINE__)

static VOID __s2e_touch_buffer(const void* Buffer, SIZE_T Size)
{
    if (!Size) {
        return;
    }

    UINT_PTR StartPage = (UINT_PTR)Buffer & ~(UINT_PTR)0xFFF;
    const UINT_PTR EndPage = (((UINT_PTR)Buffer) + Size - 1) & ~(UINT_PTR)0xFFF;

    while (StartPage <= EndPage) {
        const volatile char *b = (volatile char *)StartPage;
        *b;
        StartPage += 0x1000;
    }
}

/** Forces the read of every byte of the specified string.
  * This makes sure the memory pages occupied by the string are paged in
  * before passing them to S2E, which can't page in memory by itself. */
static VOID __s2e_touch_string(PCSTR string)
{
    const size_t len = strlen(string);
    __s2e_touch_buffer(string, len + 1);
}

/** Get S2E version or 0 when running without S2E. */
INT NTAPI S2EGetVersion(VOID);
UINT32 NTAPI S2EGetPathId(VOID);
UINT32 NTAPI S2EGetPathCount(VOID);
UINT32 NTAPI S2EGetConstraintCount(UINT_PTR Expr);
VOID NTAPI S2EGetRange(UINT_PTR Expr, UINT_PTR *Low, UINT_PTR *High);
INT NTAPI S2EGetExample(PVOID Buffer, UINT32 Size);
INT NTAPI S2EConcretize(PVOID Buffer, UINT32 Size);
INT NTAPI S2EIsSymbolic(PVOID Buffer, UINT32 Size);
VOID NTAPI S2EMakeSymbolicRaw(PVOID Buffer, UINT32 Size, PCSTR Name);
VOID NTAPI S2EMessageRaw(PCSTR Message);
INT NTAPI S2EInvokePluginRaw(PCSTR PluginName, PVOID Data, UINT32 DataSize);
INT NTAPI S2EInvokePluginConcreteModeRaw(PCSTR PluginName, PVOID Data, UINT32 DataSize);
VOID NTAPI S2EHexDump(PCSTR Name, PVOID Data, UINT32 Size);

/* Called from inside S2E. Don't invoke from guest code. */
VOID NTAPI S2EMergePointCallback(VOID);
/* Called from inside S2E. Don't invoke from guest code. */
VOID NTAPI S2EReturnHook64(VOID);

VOID NTAPI S2EAssume(UINT32 Expression);
VOID S2EAssumeDisjunction(UINT32 Variable, UINT32 Count, ...);
INT NTAPI S2EBeginAtomic(VOID);
INT NTAPI S2EEndAtomic(VOID);
VOID NTAPI S2EPrintExpression(UINT_PTR Expression, PCSTR Name);

VOID NTAPI S2EKillState(UINT32 Status, PCSTR Message);
UINT32 NTAPI S2EWriteMemory(PVOID Destination, PVOID Source, DWORD Count);

VOID NTAPI S2EDisableAllApicInterrupts(VOID);
VOID NTAPI S2EEnableAllApicInterrupts(VOID);

static inline VOID NTAPI S2EMakeSymbolic(PVOID Buffer, UINT32 Size, PCSTR Name)
{
    __s2e_touch_string(Name);
    __s2e_touch_buffer(Buffer, Size);
    S2EMakeSymbolicRaw(Buffer, Size, Name);
}

static inline INT NTAPI S2ESymbolicInt(PCSTR Name, INT InitialValue)
{
    S2EMakeSymbolic(&InitialValue, sizeof(InitialValue), Name);
    return InitialValue;
}

static inline UINT8 NTAPI S2ESymbolicChar(PCSTR Name, UINT8 InitialValue)
{
    S2EMakeSymbolic(&InitialValue, sizeof(InitialValue), Name);
    return InitialValue;
}

static inline NTSTATUS NTAPI S2ESymbolicStatus(PCSTR Name, NTSTATUS InitialValue)
{
    S2EMakeSymbolic(&InitialValue, sizeof(InitialValue), Name);
    return InitialValue;
}

static inline VOID NTAPI S2EMessage(PCSTR Message)
{
    __try {
        __s2e_touch_string(Message);
        S2EMessageRaw(Message);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("%s", Message);
    }
}

static inline INT NTAPI S2EInvokePlugin(PCSTR PluginName, PVOID Data, UINT32 DataSize)
{
    const INT Ret = 0;
    __try {
        __s2e_touch_string(PluginName);
        __s2e_touch_buffer(Data, DataSize);
        return S2EInvokePluginRaw(PluginName, Data, DataSize);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        //DbgPrint("Invoked plugin %s\n", PluginName);
    }
    return Ret;
}

static inline INT NTAPI S2EInvokePluginConcrete(PCSTR PluginName, PVOID Data, UINT32 DataSize)
{
    const INT Ret = 0;
    __try {
        return S2EInvokePluginConcreteModeRaw(PluginName, Data, DataSize);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        //DbgPrint("Invoked plugin %s\n", PluginName);
    }
    return Ret;
}

static inline VOID S2EMessageFmt(PCHAR DebugMessage, ...)
{
    va_list ap;
    CHAR String[512] = {0};
    va_start(ap, DebugMessage);
#if defined(USER_APP)
    vsprintf_s(String, sizeof(String) - 1, DebugMessage, ap);
#else
    RtlStringCbVPrintfA(String, sizeof(String) - 1, DebugMessage, ap);
#endif
    S2EMessage(String);
    va_end(ap);
}

static inline UINT32 S2EWriteMemorySafe(PVOID Destination, PVOID Source, DWORD Count)
{
    const INT Ret = 0;
    __try {
        return S2EWriteMemory(Destination, Source, Count);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("Cannot invoke S2EWriteMemory, not in S2E mode\n");
    }
    return Ret;
}

#pragma warning(pop)

#endif
