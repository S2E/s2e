/// S2E Selective Symbolic Execution Platform
///
/// Copyright (C) 2014-2020, Cyberhaven
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

#ifndef S2E_TICKLER_H

#define S2E_TICKLER_H

#include <s2e/s2e.h>

enum S2E_TICKLER_COMMANDS
{
    INIT_DONE,
    REPORT_CPU_USAGE,
    AUTOSCROLL_DONE,
    MAIN_WINDOW_OPEN,
    DONE,
    FYI,
    WINDOW_TEXT
};

struct S2E_TICKLER_CPU_USAGE
{
    UINT32 TotalCpuUsage;
    UINT32 ProgramCpuUsage;
};

struct S2E_TICKLER_COMMAND
{
    S2E_TICKLER_COMMANDS Command;

    union
    {
        S2E_TICKLER_CPU_USAGE CpuUsage;
        UINT64 AsciiZ;
    };
};

static void S2ETicklerNotifyInitDone(VOID)
{
    S2E_TICKLER_COMMAND Cmd;
    Cmd.Command = S2E_TICKLER_COMMANDS::INIT_DONE;
    S2EInvokePlugin("Tickler", &Cmd, sizeof(Cmd));
}

static void S2ETicklerReportCpuUsage(UINT32 Total, UINT32 Program)
{
    S2E_TICKLER_COMMAND Cmd;
    Cmd.Command = REPORT_CPU_USAGE;
    Cmd.CpuUsage.TotalCpuUsage = Total;
    Cmd.CpuUsage.ProgramCpuUsage = Program;
    S2EInvokePlugin("Tickler", &Cmd, sizeof(Cmd));
}

static void S2ETicklerNotifyAutoscrollDone(VOID)
{
    S2E_TICKLER_COMMAND Cmd;
    Cmd.Command = S2E_TICKLER_COMMANDS::AUTOSCROLL_DONE;
    S2EInvokePlugin("Tickler", &Cmd, sizeof(Cmd));
}

static void S2ETicklerNotifyMainWindowOpen(VOID)
{
    S2E_TICKLER_COMMAND Cmd;
    Cmd.Command = S2E_TICKLER_COMMANDS::MAIN_WINDOW_OPEN;
    S2EInvokePlugin("Tickler", &Cmd, sizeof(Cmd));
}

static void S2ETicklerSendWindowText(const char *str)
{
    S2E_TICKLER_COMMAND Cmd;
    Cmd.Command = S2E_TICKLER_COMMANDS::WINDOW_TEXT;
    Cmd.AsciiZ = (UINT_PTR)str;
    S2EInvokePlugin("Tickler", &Cmd, sizeof(Cmd));
}

static void S2ETicklerSendFYI(const char *str)
{
    S2E_TICKLER_COMMAND Cmd;
    Cmd.Command = S2E_TICKLER_COMMANDS::FYI;
    Cmd.AsciiZ = (UINT_PTR)str;
    S2EInvokePlugin("Tickler", &Cmd, sizeof(Cmd));
}

static void S2ETicklerTerminateAnalysis()
{
    S2E_TICKLER_COMMAND Cmd;
    Cmd.Command = S2E_TICKLER_COMMANDS::DONE;
    S2EInvokePlugin("Tickler", &Cmd, sizeof(Cmd));
}

#endif
