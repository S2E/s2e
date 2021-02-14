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

#define USER_APP
#include <iostream>

#include <s2e/Screenshot.h>
#include <tickler/FoxitApp.h>
#include <tickler/Tickler.h>

void FoxitApp::initCPUMonitor(PDH_HQUERY &cpuQuery)
{
    //FoxitReader has a single process
    PdhAddCounter(cpuQuery, L"\\Process(FoxitReader)\\% Processor Time", NULL, &foxitCpuTotal);
}

void FoxitApp::getCurrentCpuUsage(PLONG Total, PLONG targets)
{
    PDH_FMT_COUNTERVALUE counterVal;

    PdhGetFormattedCounterValue(foxitCpuTotal, PDH_FMT_LONG, NULL, &counterVal);
    *targets = counterVal.longValue;
}

bool FoxitApp::handleWindowOpenEventByWindowClass(BSTR &className, IUIAutomationElement *pSender)
{
    if (m_startedHandlingOpenEvent && !IsFromSameProcess(pSender)) {
        TICKLERMSG("ignoring window from different PID, taking screenshot\n");
        S2ETakeScreenshot();
        return true;
    }

    if (wcscmp(className, L"AfxFrameOrView100su") == 0) {
#if DEBUG
        std::cout << "      >> Ignoring internal Foxit window\n";
#endif
        return true;
    }

#if 0
    if (wcsncmp(className, L"Afx:", 4) == 0) {
        if (m_startedHandlingOpenEvent) {
            //this notification is delivered twice, we ignore it the second time
            //but mark the event as handled
            return true;
        }
#if DEBUG
        std::cout << "      >> Finished loading FoxIt display window\n";
#endif
        UIA_HWND _foxitWindowHandle;
        pSender->get_CurrentNativeWindowHandle(&_foxitWindowHandle);
        HWND foxitWindowHandle = (HWND)_foxitWindowHandle;
        startedHandlingOpenEvent = true;
        SetPIDFromMainWindow(pSender);
        DelayedScroll(foxitWindowHandle);
        return true;
    }
#endif

    return false;
}

bool FoxitApp::handleWindowOpenEventByWindowName(BSTR &name, IUIAutomationElement *pSender)
{
    if (m_startedHandlingOpenEvent && !IsFromSameProcess(pSender)) {
        TICKLERMSG("ignoring window from different PID, taking screenshot\n");
        S2ETakeScreenshot();
        return true;
    }

    SendWindowInfoToS2E(pSender, pAutomation);
    TICKLERMSG("clicking unknown window button\n");
    ClickDialogButton(pSender, true);
    //CloseWindow(pSender);
    //TICKLERMSG("closing unknown window\n");

    return false;
}

/**
 * FoxitReader uses a small amount of CPU when its window is focused.
 * This may prevent the analysis from being killed.
 * Unfocus the window to fix this.
 */
VOID FoxitApp::PostScrollHandler(HWND windowHandle)
{
    HWND hTopLevelWindow = getTopLevelWindow();
    TICKLERMSG("unfocusing foxit window with handle %p\n", hTopLevelWindow);

    /**
     * Minimizing and restoring the tickler's console window
     * automatically unfocuses whatever window was active.
     */
    HWND Console = GetConsoleWindow();
    TICKLERMSG("Activating console window %p\n", Console);
    ShowWindow(Console, SW_MINIMIZE);
    Sleep(2000);
    ShowWindow(Console, SW_RESTORE);
    Sleep(500);
    ShowWindow(Console, SW_SHOWMINIMIZED);
}

HWND FoxitApp::GetScrollableWindow(HWND MainWindow)
{
    unsigned Timeout = 10;
    HWND Ret;
    while (!(Ret = FindWindowWithTitleOrClass(MainWindow, "Afx:", TRUE, TRUE))) {
        TICKLERMSG("Waiting for scrollable window to appear (root=%p)...\n", MainWindow);

        Sleep(1000);
        if (--Timeout == 0) {
            return NULL;
        }
    }
    return Ret;
}
