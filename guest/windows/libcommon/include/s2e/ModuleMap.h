/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2018 Cyberhaven
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

#pragma once

#include "s2e.h"

typedef enum S2E_MODULE_MAP_COMMANDS
{
    GET_MODULE_INFO
} S2E_MODULE_MAP_COMMANDS;

typedef struct S2E_MODULE_MAP_MODULE_INFO
{
    // Specified by the guest.
    // The plugin determines which module is located at this address/pid.
    UINT64 Address;
    UINT64 Pid;

    // Pointer to storage for ASCIIZ name of the module.
    // The guest provides the pointer, the plugin sets the name.
    UINT64 ModuleName;

    // Size of the name in bytes
    UINT64 ModuleNameSize;

    UINT64 RuntimeLoadBase;
    UINT64 NativeLoadBase;
    UINT64 Size;
} S2E_MODULE_MAP_MODULE_INFO;

#pragma warning(push)
#pragma warning(disable:4201)
typedef struct S2E_MODULE_MAP_COMMAND
{
    S2E_MODULE_MAP_COMMANDS Command;

    union
    {
        S2E_MODULE_MAP_MODULE_INFO ModuleInfo;
    };
} S2E_MODULE_MAP_COMMAND;
#pragma warning(pop)

// This should be enough for anyone
#define S2E_MODULE_INFO_MAX_NAME_SIZE 64

typedef struct S2E_MODULE_INFO
{
    CHAR ModuleName[S2E_MODULE_INFO_MAX_NAME_SIZE];
    UINT64 RuntimeLoadBase;
    UINT64 NativeLoadBase;
    UINT64 Size;
} S2E_MODULE_INFO;

static BOOLEAN S2EModuleMapGetModuleInfo(UINT_PTR Address, ULONG Pid, _Out_ S2E_MODULE_INFO *Info)
{
    S2E_MODULE_MAP_COMMAND Command;

    RtlZeroMemory(Info, sizeof(*Info));

    Command.Command = GET_MODULE_INFO;
    Command.ModuleInfo.Address = Address;
    Command.ModuleInfo.Pid = Pid;
    Command.ModuleInfo.ModuleName = (UINT_PTR)Info->ModuleName;
    Command.ModuleInfo.ModuleNameSize = S2E_MODULE_INFO_MAX_NAME_SIZE;
    S2EInvokePlugin("ModuleMap", &Command, sizeof(Command));

    Info->NativeLoadBase = Command.ModuleInfo.NativeLoadBase;
    Info->RuntimeLoadBase = Command.ModuleInfo.RuntimeLoadBase;
    Info->Size = Command.ModuleInfo.Size;

    return Command.ModuleInfo.RuntimeLoadBase != 0;
}
