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

#include <stdio.h>
#include <UIAutomation.h>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <tickler/TargetApp.h>
#include <tickler/Tickler.h>

#define USER_APP

#include <s2e/s2e.h>
#include <s2e/BaseInstructions.h>
#include <s2e/Screenshot.h>
#include <s2e/Tickler.h>


/**
 * XXX: this will not work in multi-path mode
 */
void TargetApp::S2ESleepMs(UINT64 Duration)
{
    UINT64 Initial = BaseInstrGetHostClockMs();
    if (!Initial) {
        /* We are probably not in s2e mode */
        Sleep((DWORD)Duration);
        return;
    }

    UINT64 Current;
    do {
        Sleep(100);
        Current = BaseInstrGetHostClockMs();
    } while ((Current - Initial) < Duration);
}

void TargetApp::Click(int x, int y)
{
    const double XSCALEFACTOR = 65535 / (GetSystemMetrics(SM_CXSCREEN) - 1);
    const double YSCALEFACTOR = 65535 / (GetSystemMetrics(SM_CYSCREEN) - 1);

    POINT cursorPos;
    GetCursorPos(&cursorPos);

    double cx = cursorPos.x * XSCALEFACTOR;
    double cy = cursorPos.y * YSCALEFACTOR;

    double nx = x * XSCALEFACTOR;
    double ny = y * YSCALEFACTOR;

    INPUT Input = { 0 };
    Input.type = INPUT_MOUSE;

    Input.mi.dx = (LONG)nx;
    Input.mi.dy = (LONG)ny;

    Input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP;

    SendInput(1, &Input, sizeof(INPUT));

    Input.mi.dx = (LONG)cx;
    Input.mi.dy = (LONG)cy;

    Input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE;

    SendInput(1, &Input, sizeof(INPUT));
}

VOID TargetApp::PressKey(WORD vk, DWORD DelayMs)
{
    INPUT Input = { 0 };
    Input.type = INPUT_KEYBOARD;
    Input.ki.wVk = vk;
    Input.ki.wScan = 0;
    Input.ki.dwFlags = 0; //Key down
    Input.ki.time = 0;
    Input.ki.dwExtraInfo = 0;

    SendInput(1, &Input, sizeof(INPUT));
    Sleep(DelayMs);

    Input.type = INPUT_KEYBOARD;
    Input.ki.wVk = vk;
    Input.ki.wScan = 0;
    Input.ki.dwFlags = KEYEVENTF_KEYUP; //Key up
    Input.ki.time = 0;
    Input.ki.dwExtraInfo = 0;
    SendInput(1, &Input, sizeof(INPUT));
}

void TargetApp::focusWindow(HWND hWindow)
{
    TICKLERMSG("waiting for window to become foreground\n");

    for (int i = 0; i < 50; i++) {
        if (GetForegroundWindow() == hWindow) {
            return;
        }

        SetForegroundWindow(hWindow);
        Sleep(100);
    }

    TICKLERMSG("failed to make window foreground\n");
}

bool TargetApp::ClickDialogButton(IUIAutomationElement *pWindow, const std::string &buttonText)
{
    class _t : public TicklerDialogTraversal
    {
    public:
        bool m_found;
        const std::string &m_substr;

        _t(const std::string &substr) : m_found(false), m_substr(substr)
        {
        }

        virtual bool onButton(const std::wstring &text, IUIAutomationElement *pNode)
        {
            std::string str(text.begin(), text.end());
            TICKLERMSG("Button %s\n", str.c_str());

            /* We want to click on any button */
            if (m_substr.size() == 0) {
                TICKLERMSG("Clicking on first button found\n");
                return false;
            }

            std::transform(str.begin(), str.end(), str.begin(), ::tolower);

            /**
             * Buttons might have the & character for underlining.
             * Use strstr to avoid this.
             */
            if (strstr(m_substr.c_str(), str.c_str())) {
                m_found = true;

                /**
                 * This is a weird way of clicking on buttons.
                 * Some dialog buttons don't have an HWND, so only easy way is
                 * to go through UIAutomation.
                 */
                IUIAutomationInvokePattern *patternInvoke = NULL;
                HRESULT hr;
                hr = pNode->GetCurrentPatternAs(UIA_InvokePatternId, IID_PPV_ARGS(&patternInvoke));
                if (SUCCEEDED(hr) && (patternInvoke != NULL)) {
                    hr = patternInvoke->Invoke();
                    patternInvoke->Release();
                }

                return false;
            }

            return true;
        }
    };

    _t t(buttonText);
    TraverseDialog(pAutomation, pWindow, t);
    return t.m_found;
}

bool TargetApp::ClickDialogButton(IUIAutomationElement *pWindow, bool clickAny)
{
    const char *buttons[] = { "ok", "yes", "accept", "open", NULL };

    if (clickAny) {
        return ClickDialogButton(pWindow, std::string(""));
    } else {
        for (unsigned i = 0; buttons[i]; ++i) {
            if (ClickDialogButton(pWindow, std::string(buttons[i]))) {
                return true;
            }
        }
    }

    return false;
}

#define MAX_WND_TITLE 255

bool TargetApp::IsWindowWithTitleOrClass(HWND hWindow, LPCSTR Text, BOOLEAN SubString, BOOLEAN lookForClass)
{
    CHAR Buffer[MAX_WND_TITLE + 1] = { 0 };

    if (lookForClass) {
        GetClassNameA(hWindow, Buffer, MAX_WND_TITLE);
    } else {
        GetWindowTextA(hWindow, Buffer, MAX_WND_TITLE);
    }

    if (!SubString) {
        if (_stricmp(Text, Buffer) == 0) {
            return true;
        }
    } else {
        if (strstr(Buffer, Text)) {
            return true;
        }
    }

    return false;
}

HWND TargetApp::FindWindowWithTitleOrClass(HWND Root, LPCSTR Text, BOOLEAN SubString, BOOLEAN lookForClass)
{
    HWND ChildWnd = NULL;
    HWND RetVal = NULL;

    ChildWnd = GetWindow(Root, GW_CHILD);
    while (ChildWnd && RetVal == 0) {
        if (IsWindowWithTitleOrClass(ChildWnd, Text, SubString, lookForClass)) {
            return ChildWnd;
        }

        RetVal = FindWindowWithTitleOrClass(ChildWnd, Text, SubString, lookForClass);
        ChildWnd = GetWindow(ChildWnd, GW_HWNDNEXT);
    }

    return RetVal;
}

void TargetApp::setTopLevelWindow(HWND hWindow)
{
    TICKLERMSG("using main window %p\n", hWindow);
    S2ETicklerNotifyMainWindowOpen();
    S2ETakeScreenshot();

    m_topLevelWindowHandle = hWindow;
    m_startedHandlingOpenEvent = true;
    GetWindowThreadProcessId(hWindow, &m_pid);
}

bool TargetApp::isTopLevelWindow(HWND hWindow)
{
    std::string className = getTopLevelWindowClass();
    return IsWindowWithTitleOrClass(hWindow, className.c_str(), false, true);
}

/*
Scroll using JS, only works for Acrobat
*/
VOID TargetApp::DocumentScrollJS(HWND hwnd, HMENU menu)
{
    int menuItemID = GetMenuItemID(menu, GetMenuItemCount(menu) - 1);
    PostMessage(hwnd, WM_COMMAND, menuItemID, 0);
    TICKLERMSG("started JS AutoScroll\n");
#if DEBUG
    std::cout << "        >> Started JS AutoScroll\n";
#endif
}

VOID TargetApp::WaitForCpuIdle(ULONG MaxWaitTimeMs)
{
    LONG TotalCpuUsage, AppCpuUsage;
    ULONG Elapsed = 0;
    TICKLERMSG("waiting for CPU idle...\n");

    do {
        getCurrentCpuUsage(&TotalCpuUsage, &AppCpuUsage);
        S2ESleepMs(1000);
        Elapsed += 1000;
    } while (AppCpuUsage > 10 && Elapsed < MaxWaitTimeMs); //XXX: arbitrary value

    TICKLERMSG("done waiting for CPU idle\n");
}

VOID TargetApp::DocumentScroll(HWND windowHandle)
{
#if DEBUG
    std::cout << "              >> Starting regular AutoScroll\n";
#endif
    LRESULT SRet;

    /**
     * Clicking might interfere with heap spraying in some cases.
     * Wait for low cpu usage before proceeding.
     */
    WaitForCpuIdle(30 * 1000);

    windowHandle = GetScrollableWindow(windowHandle);

    /**
     * If there is no open document, don't do anything.
     * This may happen with password-protected documents,
     * docs that don't parse, etc.
     *
     * We still need to send the signal that autoscroll
     * is done in order to kill analysis after some idle time.
     */
    if (!windowHandle) {
        TICKLERMSG("no document open, skipping autoscroll\n");
        S2ETicklerNotifyAutoscrollDone();
        PostScrollHandler(windowHandle);
        return;
    }

    TICKLERMSG("scrolling window %p\n", windowHandle);

    //scroll for a max number of pages
    for (int i = 0; i < MAX_DOCUMENT_PAGES; i++) {
        TICKLERMSG("scrolling page %d\n", i);

        UINT64 CurrentTime = BaseInstrGetHostClockMs();
        UINT64 Delta = CurrentTime - m_lastTimeWindowOpened;

        if (Delta > 0 && Delta < 10000) {
            TICKLERMSG("window popped up during scrolling, sleeping...\n");
            S2ESleepMs(10000);
        }

        WaitForCpuIdle(30 * 1000);

        /* Popups might unfocus us */
        focusWindow(windowHandle);

        PrepareScroll(windowHandle);

        SRet = SendMessage(windowHandle, WM_SETFOCUS, 0, 0);
        TICKLERMSG("Send message WM_SETFOCUS returned %p\n", SRet);
        //some windows respond to page down, some respond to scroll events, so we send both
        SRet = SendMessage(windowHandle, WM_KEYDOWN, VK_NEXT, NULL);
        TICKLERMSG("Send message WM_KEYDOWN returned %p\n", SRet);

        SRet = SendMessage(windowHandle, WM_VSCROLL, SB_PAGEDOWN, 0);
        TICKLERMSG("Send message WM_VSCROLL returned %p\n", SRet);

#if DEBUG
        std::cout << "              >> Scroll to page # " << i << "\n";
#endif
        S2ESleepMs(SCROLL_DELAY);
    }

    /**
     * TODO: this stuff is very unreliable in general.
     * Replace it with PressKey events
     */
    SRet = SendMessage(windowHandle, WM_SETFOCUS, 0, 0);
    TICKLERMSG("Send message WM_SETFOCUS returned %p\n", SRet);

    SRet = SendMessage(windowHandle, WM_KEYDOWN, VK_END, NULL);
    TICKLERMSG("Send message WM_KEYDOWN returned %p\n", SRet);

    SRet = SendMessage(windowHandle, WM_VSCROLL, SB_BOTTOM, 0);
    TICKLERMSG("Send message WM_VSCROLL returned %p\n", SRet);

    /**
     * Catch all, simulate a keyboard event.
     */
    PressKey(VK_END, 500);

    S2ESleepMs(SCROLL_DELAY);

#if DEBUG
    std::cout << "              >> Scroll to end\n";
    std::cout << "              >> regular AutoScroll done\n";
#endif

    TICKLERMSG("regular AutoScroll done\n");

    S2ETicklerNotifyAutoscrollDone();
    PostScrollHandler(windowHandle);
}

struct WINDOW_DATA
{
    HWND handle;
    TargetApp *app;
};

DWORD WINAPI TargetApp::ThreadedScroll(LPVOID lpParam)
{
    WINDOW_DATA *data = (WINDOW_DATA*)lpParam;
    HWND windowHandle = data->handle;

#if SCROLL_USING_JS_API
    HMENU mainMenu = GetMenu(windowHandle);
    HMENU viewMenu = GetSubMenu(mainMenu, 2); //the View Menu
#endif

    S2ESleepMs(SCROLL_TIMEOUT);

#if SCROLL_USING_JS_API
    data->app->DocumentScrollJS(windowHandle, viewMenu);
#else
    data->app->DocumentScroll(windowHandle);
#endif
    return 0;
}

VOID TargetApp::DelayedScroll(HWND targetWindowHandle)
{
    TICKLERMSG("scheduling autoscroll for window %p\n", targetWindowHandle);

    DWORD tid;
    //create a new thread to run in background with a delay
    WINDOW_DATA *win_data =
        (WINDOW_DATA*)HeapAlloc(GetProcessHeap(),
                                HEAP_ZERO_MEMORY,
                                sizeof(WINDOW_DATA));

    win_data->handle = targetWindowHandle;
    win_data->app = this;

    HANDLE threadHandle = CreateThread(
        NULL, // default security attributes
        0, // use default stack size
        ThreadedScroll, // thread function name
        win_data, // argument to thread function
        0, // use default creation flags
        &tid); // returns the thread identifier

    if (threadHandle == NULL) {
        std::cerr << "cannot spawn thread for delayed scrolling\n";
        TICKLERMSG("cannot spawn thread for delayed scrolling\n");
    }
}
