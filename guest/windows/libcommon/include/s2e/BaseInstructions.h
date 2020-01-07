/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2015-2017 Cyberhaven
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

#ifndef BASEINSTRUCTIONS_H

#define BASEINSTRUCTIONS_H

#include "s2e.h"

typedef enum S2E_BASEINSTRUCTION_COMMANDS
{
    ALLOW_CURRENT_PID,
    GET_HOST_CLOCK_MS
} S2E_BASEINSTRUCTION_COMMANDS;

typedef struct S2E_BASEINSTRUCTION_COMMAND
{
    S2E_BASEINSTRUCTION_COMMANDS Command;
    union
    {
        UINT64 Milliseconds;
    };
} S2E_BASEINSTRUCTION_COMMAND;

static void BaseInstrAllowCurrentPid()
{
    S2E_BASEINSTRUCTION_COMMAND Command;
    Command.Command = ALLOW_CURRENT_PID;
    S2EInvokePlugin("BaseInstructions", &Command, sizeof(Command));
}

static UINT64 BaseInstrGetHostClockMs()
{
    S2E_BASEINSTRUCTION_COMMAND Command;
    Command.Command = GET_HOST_CLOCK_MS;
    Command.Milliseconds = 0;
    S2EInvokePlugin("BaseInstructions", &Command, sizeof(Command));
    return Command.Milliseconds;
}

#endif
