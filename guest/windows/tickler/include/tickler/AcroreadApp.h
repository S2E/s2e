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
#include "targetapp.h"

class AcroreadApp :
    public TargetApp
{
private:
    PDH_HCOUNTER acrobatCpuTotal0, acrobatCpuTotal1;

    bool closeLaunchExecutableWindow(IUIAutomationElement *pSender, const std::string &windowText);
    bool closeOpenFileWindow(IUIAutomationElement *pSender, const std::string &windowText);
    bool closeEmbeddedFontError(IUIAutomationElement *pSender, const std::string &windowText);
    bool closePassword(IUIAutomationElement *pSender, const std::string &windowText);
    bool closePageError(IUIAutomationElement *pSender, const std::string &windowText);
    bool closeXmlParsingError(IUIAutomationElement *pSender, const std::string &windowText);
    bool closeOpenDocumentError(IUIAutomationElement *pSender, const std::string &windowText);

    bool handleSecurityWarning(IUIAutomationElement *pSender, const std::string &windowText);

public:
    AcroreadApp()
    {
    }

    virtual std::string getName() { return "AdobeReader"; }
    virtual std::string getTopLevelWindowClass() { return "AcrobatSDIWindow"; }

    virtual void initCPUMonitor(PDH_HQUERY &cpuQuery);
    virtual void getCurrentCpuUsage(PLONG Total, PLONG targets);
    virtual bool handleWindowOpenEventByWindowClass(BSTR &className, IUIAutomationElement *pSender);
    virtual bool handleWindowOpenEventByWindowName(BSTR &name, IUIAutomationElement *pSender);
    virtual bool handleWindowCloseEventByWindowName(BSTR &name, IUIAutomationElement *pSender);
    virtual VOID PrepareScroll(HWND ScrollableWindow);
    virtual HWND GetScrollableWindow(HWND MainWindow);
};
