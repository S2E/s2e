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

#include <tickler/Tickler.h>
#include <s2e/Screenshot.h>
#include <s2e/Tickler.h>

VOID CloseWindow(IUIAutomationElement *pSender)
{
    /**
     * Sleeping should help avoiding various race conditions
     * in Acrobat that might cause it to crash.
     */
    Sleep(3);

    UIA_HWND _dialogWindowHandle;
    pSender->get_CurrentNativeWindowHandle(&_dialogWindowHandle);
    //close this window
    S2ETakeScreenshot();
    SendMessage((HWND)_dialogWindowHandle, WM_SYSCOMMAND, SC_CLOSE, 0);
}

PSTR GetSingleWindowText(HWND windowHandle)
{
    int cTxtLen = GetWindowTextLength(windowHandle);
    PSTR pszMem = (PSTR)VirtualAlloc((LPVOID)NULL, (DWORD)(cTxtLen + 1), MEM_COMMIT, PAGE_READWRITE);
    GetWindowTextA(windowHandle, pszMem, cTxtLen + 1); //TODO: check return value
    return pszMem;
}

void TraverseDescendants(IUIAutomation *pAutomation, IUIAutomationElement *pParent, std::stringstream &ss)
{
    if (pParent == NULL) return;

    IUIAutomationTreeWalker *pControlWalker = NULL;
    IUIAutomationElement *pNode = NULL;

    pAutomation->get_ControlViewWalker(&pControlWalker);
    if (pControlWalker == NULL) goto cleanup;

    pControlWalker->GetFirstChildElement(pParent, &pNode);
    if (pNode == NULL) goto cleanup;

    while (pNode) {
        UIA_HWND _windowHandle;
        pNode->get_CurrentNativeWindowHandle(&_windowHandle);
        HWND windowHandle = (HWND)_windowHandle;
        ss << GetSingleWindowText(windowHandle);
        TraverseDescendants(pAutomation, pNode, ss);
        IUIAutomationElement *pNext;
        pControlWalker->GetNextSiblingElement(pNode, &pNext);
        pNode->Release();
        pNode = pNext;
    }

cleanup:
    if (pControlWalker != NULL) pControlWalker->Release();
    if (pNode != NULL) pNode->Release();
    return;
}

std::string GetAllWindowText(IUIAutomationElement *pSender, IUIAutomation *pAutomation)
{
    std::stringstream ss;
    TraverseDescendants(pAutomation, pSender, ss);
    return ss.str();
}

void SendWindowInfoToS2E(std::string windowText)
{
    TICKLERMSG("sending window text to S2E\n");
    S2ETicklerSendWindowText(windowText.c_str());
    S2ETakeScreenshot();
}

void SendWindowInfoToS2E(IUIAutomationElement *pSender, IUIAutomation *pAutomation)
{
    //get all window text
    std::string windowText = GetAllWindowText(pSender, pAutomation);
    SendWindowInfoToS2E(windowText);
}

VOID sendFYI(const char *message)
{
    TICKLERMSG("sending FYI info, invoking SimpleCFIChecker plugin\n");
    S2ETicklerSendFYI(message);
    S2ETakeScreenshot();
}

bool TraverseDialog(IUIAutomation *pAutomation, IUIAutomationElement *root, TicklerDialogTraversal &t)
{
    bool ret = true;

    if (root == NULL) {
        return false;
    }

    IUIAutomationTreeWalker *pControlWalker = NULL;
    IUIAutomationElement *pNode = NULL;

    pAutomation->get_ControlViewWalker(&pControlWalker);
    if (pControlWalker == NULL) {
        goto cleanup;
    }

    pControlWalker->GetFirstChildElement(root, &pNode);
    if (pNode == NULL) {
        goto cleanup;
    }

    while (pNode) {
        CONTROLTYPEID type;
        pNode->get_CurrentControlType(&type);

        if (type == UIA_ButtonControlTypeId) {
            VARIANT Text;
            pNode->GetCurrentPropertyValue(UIA_NamePropertyId, &Text);
            std::wstring buttonText(Text.bstrVal, SysStringLen(Text.bstrVal));

            if (!t.onButton(buttonText, pNode)) {
                ret = false;
                goto cleanup;
            }
        }

        if (!TraverseDialog(pAutomation, pNode, t)) {
            ret = false;
            goto cleanup;
        }

        IUIAutomationElement *pNext;
        pControlWalker->GetNextSiblingElement(pNode, &pNext);
        pNode->Release();
        pNode = pNext;
    }

cleanup:
    if (pControlWalker != NULL) {
        pControlWalker->Release();
    }

    if (pNode != NULL) {
        pNode->Release();
    }

    return ret;
}
