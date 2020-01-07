/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2017 Cyberhaven
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

#ifndef S2E_RESOURCE_TRACKER

#define S2E_RESOURCE_TRACKER

#include "s2e.h"

__declspec(align(8))
typedef struct S2E_RSRCTRK_RESOURCE
{
    UINT64 ResourceId;
    UINT64 CallSite;

    /* API function that allocated/deallocated the resource */
    UINT64 LibraryName;
    UINT64 LibraryFunctionName;
} S2E_RSRCTRK_RESOURCE;

__declspec(align(8))
typedef enum S2E_RSRCTRK_COMMANDS
{
    RESOURCE_ALLOCATION,
    RESOURCE_DEALLOCATION,
    REPORT_LEAKS
} S2E_RSRCTRK_COMMANDS;

__declspec(align(8))
typedef struct S2E_RSRCTRK_COMMAND
{
    S2E_RSRCTRK_COMMANDS Command;
    union
    {
        S2E_RSRCTRK_RESOURCE Resource;
        UINT64 ModulePc;
    };
} S2E_RSRCTRK_COMMAND;

static VOID S2EAllocateResource(PCSTR LibraryFunctionName,
                         PCSTR LibraryName, UINT_PTR CallSite,
                         UINT_PTR ResourceId, BOOLEAN Allocate)
{
    S2E_RSRCTRK_COMMAND Command;
    Command.Command = Allocate ? RESOURCE_ALLOCATION : RESOURCE_DEALLOCATION;
    Command.Resource.CallSite = CallSite;
    Command.Resource.LibraryFunctionName = (UINT_PTR)LibraryFunctionName;
    Command.Resource.LibraryName = (UINT_PTR)LibraryName;
    Command.Resource.ResourceId = ResourceId;

    __s2e_touch_string(LibraryFunctionName);
    __s2e_touch_string(LibraryName);
    S2EInvokePlugin("ResourceTracker", &Command, sizeof(Command));
}

static VOID S2EResourceTrackerReportLeaks(UINT64 ModulePc)
{
    S2E_RSRCTRK_COMMAND Command;
    Command.Command = REPORT_LEAKS;
    Command.ModulePc = ModulePc;
    S2EInvokePlugin("ResourceTracker", &Command, sizeof(Command));
}

#endif
