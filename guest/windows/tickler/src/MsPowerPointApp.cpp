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

#include <tickler/MsPowerPointApp.h>
#include <tickler/Tickler.h>

#include <s2e/Screenshot.h>
#include <s2e/BaseInstructions.h>

void MsPowerPointApp::initCPUMonitor(PDH_HQUERY &cpuQuery)
{
    PdhAddCounter(cpuQuery, L"\\Process(POWERPNT)\\% Processor Time", NULL, &m_cpuTotal);
}

void MsPowerPointApp::getCurrentCpuUsage(PLONG Total, PLONG targets)
{
    PDH_FMT_COUNTERVALUE counterVal;

    PdhGetFormattedCounterValue(m_cpuTotal, PDH_FMT_LONG, NULL, &counterVal);
    *targets = counterVal.longValue;
}

bool MsPowerPointApp::handleWindowOpenEventByWindowClass(BSTR &className, IUIAutomationElement *pSender)
{
    if (!m_startedHandlingOpenEvent) {
        return true;
    }

    if (!IsFromSameProcess(pSender)) {
        TICKLERMSG("ignoring window from different PID, taking screenshot\n");
        S2ETakeScreenshot();
        return true;
    }

    return false;
}

bool MsPowerPointApp::handleWindowOpenEventByWindowName(BSTR &name, IUIAutomationElement *pSender)
{
    /* XXX: sometimes windows pop up before the main one */
    /* Close "Microsoft Office Activation Wizard" window */
    if (wcscmp(name, L"Microsoft Office Activation Wizard") == 0) {
        S2ETakeScreenshot();
        TICKLERMSG("closing Microsoft Office Activation Wizard\n");
        CloseWindow(pSender);
        return true;
    } else if (wcscmp(name, L"Password") == 0) {
        S2ETakeScreenshot();
        TICKLERMSG("Found password window, trying to open in read only mode\n");
        if (!ClickDialogButton(pSender, std::string("read only"))) {
            TICKLERMSG("  could not click on read only\n");
        }
        return true;
    }

    if (!m_startedHandlingOpenEvent) {
        return true;
    }

    if (!IsFromSameProcess(pSender)) {
        TICKLERMSG("ignoring window from different PID, taking screenshot\n");
        S2ETakeScreenshot();
        return true;
    }

    m_lastTimeWindowOpened = BaseInstrGetHostClockMs();

    UIA_HWND windowHandle;
    pSender->get_CurrentNativeWindowHandle(&windowHandle);
    SendWindowInfoToS2E(pSender, pAutomation);

    TICKLERMSG("clicking button on window %#x\n", windowHandle);
    ClickDialogButton(pSender, true);

    return false;
}

VOID MsPowerPointApp::PostScrollHandler(HWND windowHandle)
{
}

/**
 * Word needs a mouse click on the document to properly scroll.
 * Sending messages doesn't work so just press the key.
 * Don't know whether this is required for PowerPoint.
 */
VOID MsPowerPointApp::PrepareScroll(HWND ScrollableWindow)
{
    /* Find a clickable area */
    HWND ClickableWindow = FindWindowWithTitleOrClass(ScrollableWindow, "mdiClass", TRUE, TRUE);
    if (!ClickableWindow) {
        ClickableWindow = ScrollableWindow;
    }

    RECT Rect;
    if (GetWindowRect(ClickableWindow, &Rect)) {
        TICKLERMSG("GetWindowRect x:%d y:%d\n", Rect.left, Rect.top);
        Click((Rect.left + Rect.right) / 2, (Rect.top + Rect.bottom) / 2);
    } else {
        TICKLERMSG("GetWindowRect failed\n");
    }

    /**
     * TODO: need to figure out how to ensure that the pages were scrolled.
     */
    Sleep(2000);

    /* Put this in the common code eventually */
    PressKey(VK_NEXT, 500);
}

HWND MsPowerPointApp::GetScrollableWindow(HWND MainWindow)
{
    unsigned Timeout = 240; /* Can take a lot of time... */
    HWND Ret;
    while (!(Ret = FindWindowWithTitleOrClass(m_topLevelWindowHandle, "MDIClient", TRUE, TRUE))) {
        TICKLERMSG("Waiting for scrollable window to appear (root=%p)...\n", MainWindow);

        Sleep(1000);
        if (--Timeout == 0) {
            return NULL;
        }
    }

    Sleep(5000);

    /* Return the main window handle after the document appears */
    return MainWindow;
}
