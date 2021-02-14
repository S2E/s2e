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
#include <s2e/BaseInstructions.h>
#include <tickler/AcroreadApp.h>
#include <tickler/Tickler.h>

void AcroreadApp::initCPUMonitor(PDH_HQUERY &cpuQuery)
{
    //Acrobat has 2 processes, we ask to monitor them all here.
    PdhAddCounter(cpuQuery, L"\\Process(AcroRd32#0)\\% Processor Time", NULL, &acrobatCpuTotal0);
    PdhAddCounter(cpuQuery, L"\\Process(AcroRd32#1)\\% Processor Time", NULL, &acrobatCpuTotal1);
}

void AcroreadApp::getCurrentCpuUsage(PLONG Total, PLONG targets)
{
    PDH_FMT_COUNTERVALUE counterVal;

    PdhGetFormattedCounterValue(acrobatCpuTotal0, PDH_FMT_LONG, NULL, &counterVal);
    *targets = counterVal.longValue;

    PdhGetFormattedCounterValue(acrobatCpuTotal1, PDH_FMT_LONG, NULL, &counterVal);
    *targets += counterVal.longValue;
}

bool AcroreadApp::handleWindowOpenEventByWindowClass(BSTR &className, IUIAutomationElement *pSender)
{
    if (m_startedHandlingOpenEvent && !IsFromSameProcess(pSender)) {
        TICKLERMSG("ignoring window from different PID, taking screenshot\n");
        S2ETakeScreenshot();
        return true;
    }

    return false;
}

bool AcroreadApp::closeLaunchExecutableWindow(IUIAutomationElement *pSender, const std::string &windowText)
{
    if (windowText.find("This file is set to be launched by this PDF file.") == std::string::npos) {
        return false;
    }

    sendFYI("gui launch executable");
    SendWindowInfoToS2E(windowText);
    TICKLERMSG("pressing ok for launching executable\n");
    ClickDialogButton(pSender);
    return true;
}

bool AcroreadApp::closeOpenFileWindow(IUIAutomationElement *pSender, const std::string &windowText)
{
    if (windowText.find("Open the file only if you are sure it is safe") == std::string::npos) {
        return false;
    }

    sendFYI("gui open file");
    SendWindowInfoToS2E(windowText);
    TICKLERMSG("pressing ok for open file\n");
    ClickDialogButton(pSender);
    return true;
}

bool AcroreadApp::closeEmbeddedFontError(IUIAutomationElement *pSender, const std::string &windowText)
{
    if (windowText.find("Cannot extract the embedded font") == std::string::npos) {
        return false;
    }

    sendFYI("gui invalid embedded font");
    SendWindowInfoToS2E(windowText);
    TICKLERMSG("pressing ok for invalid embedded font\n");

    ClickDialogButton(pSender);
    return true;
}

bool AcroreadApp::closePassword(IUIAutomationElement *pSender, const std::string &windowText)
{
    bool asksPassword = windowText.find("The password is incorrect") != std::string::npos;
    asksPassword |= windowText.find("Password") != std::string::npos;
    if (!asksPassword) {
        return false;
    }
    sendFYI("gui requires password");
    SendWindowInfoToS2E(windowText);
    TICKLERMSG("pressing OK invalid password window\n");
    ClickDialogButton(pSender);
    return true;
}

bool AcroreadApp::closePageError(IUIAutomationElement *pSender, const std::string &windowText)
{
    if (windowText.find("An error exists on this page. Acrobat may not display the page correctly") == std::string::npos
    ) {
        return false;
    }

    SendWindowInfoToS2E(windowText);
    TICKLERMSG("pressing OK for document open error window\n");
    ClickDialogButton(pSender);
    return true;
}

bool AcroreadApp::closeXmlParsingError(IUIAutomationElement *pSender, const std::string &windowText)
{
    if (windowText.find("Xml parsing error") == std::string::npos) {
        return false;
    }

    sendFYI("gui xml parsing error");
    TICKLERMSG("pressing OK for Xml parsing error window\n");
    ClickDialogButton(pSender);
    return true;
}

bool AcroreadApp::closeOpenDocumentError(IUIAutomationElement *pSender, const std::string &windowText)
{
    if (windowText.find("There was an error opening this document") == std::string::npos) {
        return false;
    }

    sendFYI("gui file open error");
    TICKLERMSG("pressing OK for parsing error window\n");
    ClickDialogButton(pSender);
    return true;
}

bool AcroreadApp::handleSecurityWarning(IUIAutomationElement *pSender, const std::string &windowText)
{
    bool benign = false;

    if (windowText.find("The document is trying to connect to\nhttp://cgi.adobe.com/") == 0) {
        benign = true;
    } else if (windowText.find("This document is trying to connect to:\n cgi.adobe.com") == 0) {
        benign = true;
    }

    if (!benign) {
        sendFYI("gui security warning");
    } else {
        SendWindowInfoToS2E(windowText);
    }

    //UIA_HWND windowHandle;
    //pSender->get_CurrentNativeWindowHandle(&windowHandle);
    //This needs to be tested properly
    //SendMessage((HWND) windowHandle, WM_COMMAND, 2, NULL);  //press Allow button
    //TICKLERMSG("pressing Allow for Security Warning window\n");
    return true;
}

bool AcroreadApp::handleWindowOpenEventByWindowName(BSTR &name, IUIAutomationElement *pSender)
{
    if (!m_startedHandlingOpenEvent) {
        return true;
    }

    if (!IsFromSameProcess(pSender)) {
        TICKLERMSG("ignoring window from different PID, taking screenshot\n");
        S2ETakeScreenshot();
        return true;
    }

    /**
     * Sometimes windows popup in the middle of scrolling,
     * need to wait a bit more. This records the last time
     * a window got opened. The scroller checks it and waits
     * if the open is too recent, in order to let the window close.
     *
     * It is not possible to disable scrolling here and enable
     * it again in the onWindowClose() event because that event is
     * not always triggered. Scrolling is never enabled again,
     * the scrolling done signal is not sent to S2E, and the analyses
     * is stuck until it times out.
     */
    m_lastTimeWindowOpened = BaseInstrGetHostClockMs();

    if (wcsncmp(name, L"Reading", 7) == 0) {
        TICKLERMSG("closing Reading window\n");
        CloseWindow(pSender);
    } else if (wcsncmp(name, L"Accessibility", 13) == 0) {
        TICKLERMSG("closing Accesibility window\n");
        CloseWindow(pSender);
    } else if (wcsncmp(name, L"Security Warning", 16) == 0) {
        std::string windowText = GetAllWindowText(pSender, pAutomation);
        handleSecurityWarning(pSender, windowText);
    } else if (wcsncmp(name, L"Save As", 7) == 0) {
        sendFYI("gui save file");
        //TODO: implement click on Save As to see the action happening
        //ClickSave(pSender);
    } else if (wcsncmp(name, L"Open File", 9) == 0) {
        std::string windowText = GetAllWindowText(pSender, pAutomation);
        closeOpenFileWindow(pSender, windowText);
    } else if (wcsncmp(name, L"Warning: JavaScript Window", 20) == 0) {
        TICKLERMSG("pressing ok for Warning: JavaScript Window\n");
        ClickDialogButton(pSender);
        //clicking can fail if the window is not in focus, so we can close the window instead
        CloseWindow(pSender);
    } else if (wcsncmp(name, L"Note For Users of Assistive Technology", 37) == 0) {
        TICKLERMSG("pressing OK for Note For Users of Assistive Technology Window\n");
        S2ETakeScreenshot();
        ClickDialogButton(pSender);
    } else if (wcsncmp(name, L"Adobe Reader", 12) == 0) {
        std::string windowText = GetAllWindowText(pSender, pAutomation);
        closeOpenDocumentError(pSender, windowText);
        closeXmlParsingError(pSender, windowText);
        closePageError(pSender, windowText);
        closeLaunchExecutableWindow(pSender, windowText);
        closeEmbeddedFontError(pSender, windowText);
        closePassword(pSender, windowText);
        closeOpenFileWindow(pSender, windowText);
    } else if (wcsncmp(name, L"Beyond Adobe Reader", 19) == 0) {
        TICKLERMSG("closing Beyond Adobe Reader window\n");
        S2ETakeScreenshot();
        CloseWindow(pSender);
    } else if (wcsncmp(name, L"Launch File", 11) == 0) {
        TICKLERMSG("pressing open for launching executable\n");
        S2ETakeScreenshot();
        sendFYI("gui launch executable");
        SendWindowInfoToS2E(pSender, pAutomation);
        ClickDialogButton(pSender); //press open button
    } else {
        //Workardound the fact that the Open File window can appear with
        //an unexpected window name, so we need to pattern match on the displayed text
        //and try to close it here instead.
        std::string windowText = GetAllWindowText(pSender, pAutomation);
        closeOpenFileWindow(pSender, windowText);

        //TODO: double check this
        SendWindowInfoToS2E(pSender, pAutomation);
        TICKLERMSG("clicking unknown window button\n");
        ClickDialogButton(pSender, true);
        //CloseWindow(pSender);
        //TICKLERMSG("closing unknown window\n");
    }
    return false;
}

/**
 * Track the window close event for debugging. Not used otherwise.
 */
bool AcroreadApp::handleWindowCloseEventByWindowName(BSTR &name, IUIAutomationElement *pSender)
{
    if (!m_startedHandlingOpenEvent) {
        return false;
    }

    if (!IsFromSameProcess(pSender)) {
        TICKLERMSG("ignoring window from different PID, taking screenshot\n");
        S2ETakeScreenshot();
        return false;
    }

    m_lastTimeWindowOpened = BaseInstrGetHostClockMs();
    return true;
}

/**
 * Acrobat needs a mouse click on the document to properly scroll.
 */
VOID AcroreadApp::PrepareScroll(HWND ScrollableWindow)
{
    RECT Rect;
    if (GetWindowRect(ScrollableWindow, &Rect)) {
        TICKLERMSG("GetWindowRect x:%d y:%d\n", Rect.left, Rect.top);
        Click(Rect.left + 10, Rect.top + 10);
    } else {
        TICKLERMSG("GetWindowRect failed\n");
    }
}

HWND AcroreadApp::GetScrollableWindow(HWND MainWindow)
{
    unsigned Timeout = 10;
    HWND Ret;
    while (!(Ret = FindWindowWithTitleOrClass(MainWindow, "AVSplitationPageView", TRUE, FALSE))) {
        TICKLERMSG("Waiting for scrollable window to appear (root=%p)...\n", MainWindow);

        Sleep(1000);
        if (--Timeout == 0) {
            return NULL;
        }
    }
    return Ret;
}
