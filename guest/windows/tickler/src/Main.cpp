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

#include <windows.h>
#include <stdio.h>
#include <UIAutomation.h>
#include <iostream>
#include <sstream>

#include <s2e/BaseInstructions.h>
#include <s2e/Tickler.h>

#include <tickler/Tickler.h>
#include <tickler/TargetApp.h>
#include <tickler/AcroreadApp.h>
#include <tickler/FoxitApp.h>
#include <tickler/MsWordApp.h>
#include <tickler/MsExcelApp.h>
#include <tickler/MsPowerPointApp.h>

VOID StartCpuMonitor(TargetApp *app);

class EventHandler : public IUIAutomationEventHandler
{
private:
    LONG _refCount;
    TargetApp *app;
    std::set<UIA_HWND> opened_windows;

public:
    int _eventCount;

    // Constructor.
    EventHandler(TargetApp *_app) : _refCount(1), _eventCount(0)
    {
        this->app = _app;
    }

    ~EventHandler()
    {
    }

    // IUnknown methods.
    ULONG STDMETHODCALLTYPE AddRef()
    {
        ULONG ret = InterlockedIncrement(&_refCount);
        return ret;
    }

    ULONG STDMETHODCALLTYPE Release()
    {
        ULONG ret = InterlockedDecrement(&_refCount);
        if (ret == 0) {
            delete this;
            return 0;
        }
        return ret;
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppInterface)
    {
        if (riid == __uuidof(IUnknown)) {
            *ppInterface = static_cast<IUIAutomationEventHandler*>(this);
        } else if (riid == __uuidof(IUIAutomationEventHandler)) {
            *ppInterface = static_cast<IUIAutomationEventHandler*>(this);
        } else {
            *ppInterface = NULL;
            return E_NOINTERFACE;
        }
        this->AddRef();
        return S_OK;
    }

    VOID printSenderInfo(IUIAutomationElement *pSender)
    {
        HRESULT h;
        BSTR name;
        BSTR className;
        BSTR providerDescription;

        h = pSender->get_CurrentName(&name);
        if (SUCCEEDED(h)) {
            wprintf(L"   >> UI element name: %ls ", name);
            SysFreeString(name);
        }

        h = pSender->get_CurrentClassName(&className);
        if (SUCCEEDED(h)) {
            wprintf(L"class: %ls ", className);
            SysFreeString(className);
        }

        int pid;
        h = pSender->get_CurrentProcessId(&pid);
        if (SUCCEEDED(h)) {
            wprintf(L"pid: %d ", pid);
        }

        pSender->get_CurrentProviderDescription(&providerDescription);
        if (SUCCEEDED(h)) {
            wprintf(L"type: %ls ", providerDescription);
            SysFreeString(providerDescription);
        }

        wprintf(L"\n");
    }

    // IUIAutomationEventHandler methods
    HRESULT STDMETHODCALLTYPE HandleAutomationEvent(IUIAutomationElement *pSender, EVENTID eventID)
    {
        _eventCount++;

        switch (eventID) {
            case UIA_Window_WindowOpenedEventId:
                HandleWindowOpenedEvent(pSender);
                break;

            case UIA_Window_WindowClosedEventId:
                HandleWindowClosedEvent(pSender);
                break;

            default:
                std::cerr << ">> Unhandled event " << eventID << " event count " << _eventCount << std::endl;
                break;
        }

        return S_OK;
    }

    void printOpenedWindowInfo(IUIAutomationElement *pSender)
    {
        BSTR name = NULL, className = NULL;
        UIA_HWND hwnd = NULL;

        pSender->get_CurrentClassName(&className);
        pSender->get_CurrentName(&name);
        pSender->get_CurrentNativeWindowHandle(&hwnd);

        TICKLERMSG("new window: hwnd %p, name '%S', class '%S'\n", hwnd, name, className);
    }

    void HandleWindowOpenedEvent(IUIAutomationElement *pSender)
    {
        printOpenedWindowInfo(pSender);

        UIA_HWND hwnd = NULL;
        pSender->get_CurrentNativeWindowHandle(&hwnd);

        // Sometimes we receive duplicates of open event for the same window
        if (opened_windows.find(hwnd) != opened_windows.end()) {
            TICKLERMSG("ignoring open event for the same window %p\n", hwnd);
            return;
        }

        // TODO: remove ids on close event, they could be not unique
        opened_windows.insert(hwnd);

        if (!app->getTopLevelWindow()) {
            if (app->isTopLevelWindow((HWND)hwnd)) {
                app->setTopLevelWindow((HWND)hwnd);
                return;
            }
        }

        BSTR className;
        if (SUCCEEDED(pSender->get_CurrentClassName(&className))) {
            bool handled = app->handleWindowOpenEventByWindowClass(className, pSender);
            SysFreeString(className);
            if (handled) {
                return;
            }
        }

        BSTR name;
        if (SUCCEEDED(pSender->get_CurrentName(&name))) {
            bool handled = app->handleWindowOpenEventByWindowName(name, pSender);
            SysFreeString(name);
            if (handled) {
                return;
            }
        }
    }

    void HandleWindowClosedEvent(IUIAutomationElement *pSender)
    {
        // have to use pSender->GetRuntimeId because UI element is already deleted
    }
};

static VOID LaunchAndWaitForRealTickler(PCSTR Command, PCSTR Arguments)
{
    HANDLE Semaphore;
    SECURITY_ATTRIBUTES Attributes;

    Attributes.nLength = sizeof(Attributes);
    Attributes.lpSecurityDescriptor = NULL;
    Attributes.bInheritHandle = TRUE;

    Semaphore = CreateSemaphore(&Attributes, 0, 1, NULL);

    if (Semaphore == NULL) {
        S2EKillState(GetLastError(), "could not init semaphore");
        return;
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    std::stringstream newCmdLine;
    newCmdLine << Command << " " << Arguments << " " << std::hex << "0x" << (UINT_PTR)Semaphore;

    char *c = _strdup(newCmdLine.str().c_str());

    TICKLERMSG("starting %s\n", c);

    if (!CreateProcessA(NULL, c, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        S2EKillState(GetLastError(), "could not start tickler\n");
        goto err1;
    }

    TICKLERMSG("waiting for child to initialize...\n");

    DWORD Res = WaitForSingleObject(Semaphore, 40000);
    if (Res != WAIT_OBJECT_0) {
        S2EKillState(Res, "could not wait for semaphore\n");
        goto err1;
    }

    TICKLERMSG("done waiting for tickler\n");

err1:
    free(c);
    CloseHandle(Semaphore);
}

int main(int argc, char *argv[])
{
    HRESULT hr;
    int ret = 0;
    IUIAutomationElement *pTargetElement = NULL;
    EventHandler *pEHTemp = NULL;
    HANDLE Semaphore = NULL;
    TargetApp *targetApp;

    TICKLERMSG("starting ... (built on %s %s)\n", __DATE__, __TIME__);

    if (argc != 2 && argc != 3) {
        TICKLERMSG("Usage: %s appname [semhandle]\n", argv[0]);
        exit(-1);
    }

    if (argc == 2) {
        LaunchAndWaitForRealTickler(argv[0], argv[1]);
        exit(0);
    } else {
        if (strcmp(argv[1], "AdobeReader") == 0) {
            targetApp = new AcroreadApp();
            TICKLERMSG("target app: AdobeReader (configured)\n");
        } else if (strcmp(argv[1], "FoxitReader") == 0) {
            targetApp = new FoxitApp();
            TICKLERMSG("target app: FoxitReader (configured)\n");
        } else if (strcmp(argv[1], "MsWord") == 0) {
            targetApp = new MsWordApp();
            TICKLERMSG("target app: MsWord (configured)\n");
        } else if (strcmp(argv[1], "MsExcel") == 0) {
            targetApp = new MsExcelApp();
            TICKLERMSG("target app: MsExcel (configured)\n");
        } else if (strcmp(argv[1], "MsPowerPoint") == 0) {
            targetApp = new MsPowerPointApp();
            TICKLERMSG("target app: MsPowerPoint (configured)\n");
        } else {
            std::cerr << "unsupported app, exiting\n";
            TICKLERMSG("unsupported app, exiting\n");
            exit(1);
        }

        Semaphore = (HANDLE)_strtoui64(argv[2], NULL, 0);
        if (Semaphore == NULL) {
            S2EKillState(0, "Invalid semaphore handle");
            exit(1);
        }
    }

    S2ETicklerNotifyInitDone();

    // Only the tickler will be able to use custom instructions.
    BaseInstrAllowCurrentPid();

    StartCpuMonitor(targetApp);

    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    IUIAutomation *pAutomation = NULL;
    hr = CoCreateInstance(__uuidof(CUIAutomation), NULL,
                          CLSCTX_INPROC_SERVER, __uuidof(IUIAutomation), (void**)&pAutomation);
    if (FAILED(hr) || pAutomation == NULL) {
        ret = -1;
        goto cleanup;
    }

    // Use root element for listening to window creation and destruction.
    hr = pAutomation->GetRootElement(&pTargetElement);
    if (FAILED(hr) || pTargetElement == NULL) {
        ret = -2;
        goto cleanup;
    }

    targetApp->setAutomation(pAutomation);

    pEHTemp = new EventHandler(targetApp);
    if (pEHTemp == NULL) {
        ret = -3;
        goto cleanup;
    }

    TICKLERMSG("adding window open event handlers\n");

    hr = pAutomation->AddAutomationEventHandler(UIA_Window_WindowOpenedEventId,
                                                pTargetElement, TreeScope_Subtree, NULL,
                                                (IUIAutomationEventHandler*)pEHTemp);

    if (FAILED(hr)) {
        ret = -4;
        goto cleanup;
    }

    TICKLERMSG("adding window close event handlers\n");

    hr = pAutomation->AddAutomationEventHandler(UIA_Window_WindowClosedEventId,
                                                pTargetElement, TreeScope_Subtree, NULL,
                                                (IUIAutomationEventHandler*)pEHTemp);
    if (FAILED(hr)) {
        ret = -5;
        goto cleanup;
    }

    /* Minimize all windows */
    HWND hwnd = FindWindowA("Shell_TrayWnd", NULL);
    LRESULT res = SendMessageA(hwnd, WM_COMMAND, (WPARAM)419, 0);

    /**
     * Notify the parent that we started.
     */
    TICKLERMSG("ready to start application\n");
    if (Semaphore != (HANDLE)-1) {
        TICKLERMSG("releasing semaphore\n");
        ReleaseSemaphore(Semaphore, 1, NULL);
    }

    /* Wait until main window is found */
    TICKLERMSG("waiting for top level window...\n");
    while (!targetApp->getTopLevelWindow()) {
        Sleep(1000);
    }

    /* NOTE!
     * Do not focus main window, you will get race condition with
     * focusing popup dialogs in ClickDialogButton.
     */

    /**
     * Schedule scroll right after the main window is started.
     * This doesn't need UI Automator.
     */
    TICKLERMSG("scheduling delayed scroll\n");
    targetApp->DelayedScroll(targetApp->getTopLevelWindow());

    TICKLERMSG("press any key to remove event handlers and exit\n");
    getchar();

    TICKLERMSG("removing event handlers.\n");

cleanup:

    TICKLERMSG("cleaning up (status=%d)\n", ret);
    S2EKillState(-1, "tickler is terminated");

    // Remove event handlers, release resources, and terminate
    if (pAutomation != NULL) {
        hr = pAutomation->RemoveAllEventHandlers();
        if (FAILED(hr)) {
            ret = -6;
        }
        pAutomation->Release();
    }

    if (pEHTemp != NULL) {
        pEHTemp->Release();
    }

    if (pTargetElement != NULL) {
        pTargetElement->Release();
    }

    CoUninitialize();

    delete targetApp;

    if (ret < 0) {
        return 1;
    } else {
        return 0;
    }

    return ret;
}
