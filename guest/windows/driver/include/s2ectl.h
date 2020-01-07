/// S2E Selective Symbolic Execution Platform
///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2018, Cyberhaven
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

/// This is a standalone header file that you can use in your projects
/// to interact with the S2E driver. Make sure to define the USER_APP
/// macro first.
///
/// If you cannot use S2E instructions in your program, you can use this
/// header to call the driver using standard Windows APIs in order to have it
/// run the custom instructions instead. This may be handy when it is too
/// cumbersome to add external object files that implement custom instructions.

#ifndef __S2E_CTL__

#define __S2E_CTL__

#if defined(USER_APP)
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>

static TCHAR S2EDriverDevice[] = _T("\\\\.\\\\S2EDriver");
#endif

#define FSCTL_S2E_BASE      FILE_DEVICE_UNKNOWN

#define _S2E_CTL_CODE(_Function, _Method, _Access)  \
            CTL_CODE(FSCTL_S2E_BASE, _Function, _Method, _Access)

#define IOCTL_S2E_REGISTER_MODULE   \
            _S2E_CTL_CODE(0x200, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_S2E_CUSTOM_BUG   \
            _S2E_CTL_CODE(0x201, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_S2E_WINDOWS_USERMODE_CRASH   \
            _S2E_CTL_CODE(0x202, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_S2E_CRASH_KERNEL   \
            _S2E_CTL_CODE(0x203, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_S2E_SET_CONFIG   \
            _S2E_CTL_CODE(0x204, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_S2E_INVOKE_PLUGIN   \
            _S2E_CTL_CODE(0x205, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_S2E_MAKE_SYMBOLIC   \
            _S2E_CTL_CODE(0x206, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_S2E_GET_PATH_ID   \
            _S2E_CTL_CODE(0x207, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#pragma warning(push)
#pragma warning(disable: 4200)
typedef struct
{
    // Total size of this structure (in bytes)
    UINT64 Size;

    UINT64 Value;

    // ASCIIZ string
    CHAR Name[];
} S2E_IOCTL_SET_CONFIG;

typedef struct
{
    // Total size of this structure in bytes (including name and data)
    UINT32 Size;
    UINT32 PluginNameOffset;
    UINT32 PluginNameSize;
    UINT32 DataOffset;
    UINT32 DataSize;
    UINT32 Result;
} S2E_IOCTL_INVOKE_PLUGIN;

typedef struct
{
    UINT64 VariableNamePointer;
    UINT64 DataPointer;
    UINT32 VariableNameSize;
    UINT32 DataSize;
} S2E_IOCTL_MAKE_SYMBOLIC;

typedef struct
{
    UINT64 PathId;
} S2E_IOCTL_GET_PATH_ID;

#pragma warning(pop)

#if defined(USER_APP)
static HANDLE S2EOpenDriver(LPCTSTR DeviceName)
{
    return CreateFile(
        DeviceName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        (HANDLE)INVALID_HANDLE_VALUE
    );
}

static BOOL S2EIoCtl(HANDLE Handle, DWORD Code, PVOID Buffer, DWORD Length)
{
    CHAR Output[128];
    DWORD BytesReturned;
    return DeviceIoControl(Handle, Code, Buffer, Length, Output, sizeof(Output), &BytesReturned, NULL);
}

static BOOL S2EIoCtlOut(HANDLE Handle, DWORD Code, PVOID Buffer, DWORD Length)
{
    DWORD BytesReturned;
    return DeviceIoControl(Handle, Code, Buffer, Length, Buffer, Length, &BytesReturned, NULL);
}

static S2E_IOCTL_SET_CONFIG *S2ESerializeIoctlSetConfig(LPCSTR Name, UINT64 Value)
{
    size_t NameSize = strlen(Name) + 1;
    size_t Length = sizeof(S2E_IOCTL_SET_CONFIG) + NameSize;
    S2E_IOCTL_SET_CONFIG *Ret = (S2E_IOCTL_SET_CONFIG*) malloc(Length);
    if (!Ret) {
        return NULL;
    }

    Ret->Size = Length;
    Ret->Value = Value;
    memcpy(Ret->Name, Name, NameSize);
    return Ret;
}

static BOOL S2EIoctlSetConfig(HANDLE Driver, LPCSTR Name, UINT64 Value)
{
    S2E_IOCTL_SET_CONFIG *Cfg = S2ESerializeIoctlSetConfig(Name, Value);
    if (!Cfg) {
        return FALSE;
    }

    BOOL Ret = S2EIoCtl(Driver, IOCTL_S2E_SET_CONFIG, Cfg, (DWORD) Cfg->Size);

    free(Cfg);
    return Ret;
}

// Invokes a plugin through the driver.
// This works the same as the S2EInvokePlugin API, except that it also
// returns an additional pointer to where the driver stores the plugins's output.
// This pointer always points inside the S2E_IOCTL_INVOKE_PLUGIN buffer returned by this function.
static S2E_IOCTL_INVOKE_PLUGIN *S2ESerializeIoctlInvokePlugin(LPCSTR PluginName, LPCVOID Data, UINT32 Size, PVOID *Output)
{
    size_t PluginNameSize = strlen(PluginName) + 1;
    size_t Length = sizeof(S2E_IOCTL_INVOKE_PLUGIN) + PluginNameSize + Size;
    S2E_IOCTL_INVOKE_PLUGIN *Ret = (S2E_IOCTL_INVOKE_PLUGIN*)malloc(Length);
    if (!Ret) {
        return NULL;
    }

    Ret->Size = (UINT32) Length;

    UINT32 Offset = sizeof(S2E_IOCTL_INVOKE_PLUGIN);

    Ret->PluginNameOffset = Offset;
    Ret->PluginNameSize = (UINT32) PluginNameSize;
    memcpy((PVOID)(((UINT_PTR)Ret) + Offset), PluginName, PluginNameSize);
    Offset += Ret->PluginNameSize;

    Ret->DataOffset = Offset;
    Ret->DataSize = Size;

    *Output = (PVOID)(((UINT_PTR)Ret) + Offset);
    memcpy(*Output, Data, Size);

    return Ret;
}

static BOOL S2EIoctlMakeSymbolic(HANDLE Driver, LPCSTR VariableName, LPVOID Data, UINT32 Size)
{
    S2E_IOCTL_MAKE_SYMBOLIC Req;

    Req.VariableNamePointer = (UINT_PTR)VariableName;
    Req.VariableNameSize = (UINT32)(strlen(VariableName) + 1);
    Req.DataPointer = (UINT_PTR)Data;
    Req.DataSize = Size;

    return S2EIoCtl(Driver, IOCTL_S2E_MAKE_SYMBOLIC, &Req, sizeof(Req));
}

static BOOL S2EIoctlGetPathId(HANDLE Driver, UINT64 *PathId)
{
    S2E_IOCTL_GET_PATH_ID Req;
    BOOL Ret = S2EIoCtlOut(Driver, IOCTL_S2E_GET_PATH_ID, &Req, sizeof(Req));
    *PathId = Req.PathId;
    return Ret;
}

#endif

#endif
