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
///

#include <iostream>
#include "pdh.h"
#include <tickler/TargetApp.h>
#include <tickler/Tickler.h>

#define USER_APP

#include <s2e/Tickler.h>

static PDH_HQUERY cpuQuery;
static PDH_HCOUNTER cpuTotal;
static TargetApp *app;

static void initCPUMonitor()
{
    PdhOpenQuery(NULL, NULL, &cpuQuery);

    PdhAddCounter(cpuQuery, L"\\Processor(_Total)\\% Processor Time", NULL, &cpuTotal);

    app->initCPUMonitor(cpuQuery);

    PdhCollectQueryData(cpuQuery);
}

static void cleanCPUMonitor()
{
    PdhCloseQuery(cpuQuery);
}

static void getCurrentCpuUsage(PLONG Total, PLONG targets)
{
    PDH_FMT_COUNTERVALUE counterVal;

    PdhCollectQueryData(cpuQuery);

    PdhGetFormattedCounterValue(cpuTotal, PDH_FMT_LONG, NULL, &counterVal);
    *Total = counterVal.longValue;

    app->getCurrentCpuUsage(Total, targets);
}

static DWORD WINAPI CpuMonitorThread(LPVOID Unused)
{
    initCPUMonitor();

    while (1) {
        LONG Total, Target;
        getCurrentCpuUsage(&Total, &Target);
        TICKLERMSG("CPU usage: %d Target %s: %d\n", Total, app->getName().c_str(), Target);
        S2ETicklerReportCpuUsage((UINT)Total, (UINT)Target);
        TargetApp::S2ESleepMs(2000);
    }

    cleanCPUMonitor();

    return 0;
}

VOID StartCpuMonitor(TargetApp *targetApp)
{
    app = targetApp;
    HANDLE hThread = CreateThread(
        NULL, // default security attributes
        0, // use default stack size
        CpuMonitorThread, // thread function name
        NULL, // argument to thread function
        0, // use default creation flags
        NULL); // returns the thread identifier

    if (hThread == NULL) {
        std::cout << "cannot spawn thread for delayed scrolling\n";
        TICKLERMSG("cannot spawn thread for delayed scrolling\n");
    }
}
