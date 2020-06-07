/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2017-2020 Cyberhaven
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

#include <s2e/s2e.h>

VOID __s2e_touch_buffer(const void *Buffer, SIZE_T Size)
{
    if (!Size) {
        return;
    }

    UINT_PTR StartPage = (UINT_PTR)Buffer & ~(UINT_PTR)0xFFF;
    const UINT_PTR EndPage = (((UINT_PTR)Buffer) + Size - 1) & ~(UINT_PTR)0xFFF;

    while (StartPage <= EndPage) {
        const volatile char *b = (volatile char*)StartPage;
        *b;
        StartPage += 0x1000;
    }
}

/** Forces the read of every byte of the specified string.
  * This makes sure the memory pages occupied by the string are paged in
  * before passing them to S2E, which can't page in memory by itself. */
VOID __s2e_touch_string(PCSTR string)
{
    const size_t len = strlen(string);
    __s2e_touch_buffer(string, len + 1);
}

VOID NTAPI S2EMakeSymbolic(PVOID Buffer, UINT32 Size, PCSTR Name)
{
    __s2e_touch_string(Name);
    __s2e_touch_buffer(Buffer, Size);
    S2EMakeSymbolicRaw(Buffer, Size, Name);
}

INT NTAPI S2ESymbolicInt(PCSTR Name, INT InitialValue)
{
    S2EMakeSymbolic(&InitialValue, sizeof(InitialValue), Name);
    return InitialValue;
}

UINT8 NTAPI S2ESymbolicChar(PCSTR Name, UINT8 InitialValue)
{
    S2EMakeSymbolic(&InitialValue, sizeof(InitialValue), Name);
    return InitialValue;
}

NTSTATUS NTAPI S2ESymbolicStatus(PCSTR Name, NTSTATUS InitialValue)
{
    S2EMakeSymbolic(&InitialValue, sizeof(InitialValue), Name);
    return InitialValue;
}

VOID NTAPI S2EMessage(PCSTR Message)
{
    __try {
        __s2e_touch_string(Message);
        S2EMessageRaw(Message);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("%s", Message);
    }
}

INT NTAPI S2EInvokePlugin(PCSTR PluginName, PVOID Data, UINT32 DataSize)
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

INT NTAPI S2EInvokePluginConcrete(PCSTR PluginName, PVOID Data, UINT32 DataSize)
{
    const INT Ret = 0;
    __try {
        return S2EInvokePluginConcreteModeRaw(PluginName, Data, DataSize);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        //DbgPrint("Invoked plugin %s\n", PluginName);
    }
    return Ret;
}

VOID S2EMessageFmt(PCHAR DebugMessage, ...)
{
    va_list ap;
    CHAR String[512] = { 0 };
    va_start(ap, DebugMessage);
#if defined(USER_APP)
    vsprintf_s(String, sizeof(String) - 1, DebugMessage, ap);
#else
    RtlStringCbVPrintfA(String, sizeof(String) - 1, DebugMessage, ap);
#endif
    S2EMessage(String);
    va_end(ap);
}

UINT32 S2EWriteMemorySafe(PVOID Destination, PVOID Source, DWORD Count)
{
    const INT Ret = 0;
    __try {
        return S2EWriteMemory(Destination, Source, Count);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("Cannot invoke S2EWriteMemory, not in S2E mode\n");
    }
    return Ret;
}
