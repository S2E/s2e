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

#pragma once

#include <string>
#include "pdh.h"
#include <UIAutomation.h>
#include <set>
#include <vector>

class TargetApp
{
protected:
    IUIAutomation *pAutomation;
    DWORD m_pid;
    HWND m_topLevelWindowHandle;
    volatile bool m_startedHandlingOpenEvent;

    volatile UINT64 m_lastTimeWindowOpened;

    VOID DocumentScrollJS(HWND hwnd, HMENU menu);
    VOID DocumentScroll(HWND windowHandle);
    static DWORD WINAPI ThreadedScroll(LPVOID lpParam);

    virtual VOID PostScrollHandler(HWND windowHandle)
    {
    };

public:
    static VOID S2ESleepMs(UINT64 Duration);
    static VOID Click(int x, int y);
    static VOID PressKey(WORD vk, DWORD DelayMs);
    static bool IsWindowWithTitleOrClass(HWND hWindow, LPCSTR Text, BOOLEAN SubString, BOOLEAN lookForClass);
    static HWND FindWindowWithTitleOrClass(HWND Root, LPCSTR Text, BOOLEAN SubString, BOOLEAN lookForClass);
    void FindButtons(IUIAutomationElement *pParent, std::vector<std::pair<HWND, std::string>> &ret);

    bool ClickDialogButton(IUIAutomationElement *pWindow, const std::string &buttonText);
    bool ClickDialogButton(IUIAutomationElement *pParent, bool clickAny = false);

    TargetApp() : pAutomation(NULL), m_pid(-1), m_topLevelWindowHandle(NULL),
                  m_startedHandlingOpenEvent(false), m_lastTimeWindowOpened(0)
    {
    }

    virtual std::string getName() = 0;

    virtual std::string getTopLevelWindowClass() = 0;
    HWND getTopLevelWindow() { return m_topLevelWindowHandle; }
    void setTopLevelWindow(HWND hWindow);
    bool isTopLevelWindow(HWND hWindow);

    VOID WaitForCpuIdle(ULONG MaxWaitTimeMs);
    VOID DelayedScroll(HWND targetWindowHandle);
    void focusWindow(HWND hWindow);

    virtual bool IsFromSameProcess(IUIAutomationElement *pSender)
    {
        int tmp;
        if (SUCCEEDED(pSender->get_CurrentProcessId(&tmp))) {
            return m_pid == tmp;
        } else {
            return false;
        }
    }

    virtual HWND GetScrollableWindow(HWND MainWindow) = 0;
    virtual VOID PrepareScroll(HWND ScrollableWindow) = 0;
    virtual void setAutomation(IUIAutomation *_pAutomation) { pAutomation = _pAutomation; }
    virtual void initCPUMonitor(PDH_HQUERY &cpuQuery) = 0;
    virtual void getCurrentCpuUsage(PLONG Total, PLONG targets) = 0;
    virtual bool handleWindowOpenEventByWindowClass(BSTR &name, IUIAutomationElement *pSender) = 0;
    virtual bool handleWindowOpenEventByWindowName(BSTR &name, IUIAutomationElement *pSender) = 0;
    virtual bool handleWindowCloseEventByWindowName(BSTR &name, IUIAutomationElement *pSender) = 0;
};
