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

#define DEBUG 0

#define SCROLL_USING_JS_API 0
#define MAX_DOCUMENT_PAGES 10
#define SCROLL_DELAY 500 //0.5 sec
#define SCROLL_TIMEOUT 20000 //20 secs


#define USER_APP

#include <s2e/s2e.h>

#define TICKLERMSG(a, ...) S2EMessageFmt("tickler: " ## a, __VA_ARGS__)

void CloseWindow(IUIAutomationElement *pSender);

void SendWindowInfoToS2E(std::string windowText);

void SendWindowInfoToS2E(IUIAutomationElement *pSender, IUIAutomation *pAutomation);

void sendFYI(const char *message);

std::string GetAllWindowText(IUIAutomationElement *pSender, IUIAutomation *pAutomation);

/* Override class to take specific actions when each control it visited */
class TicklerDialogTraversal
{
public:
    virtual bool onButton(const std::wstring &text, IUIAutomationElement *pNode)
    {
        return true;
    }
};

bool TraverseDialog(IUIAutomation *pAutomation, IUIAutomationElement *root, TicklerDialogTraversal &t);
