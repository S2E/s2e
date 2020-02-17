///
/// Copyright (C) 2018, Cyberhaven
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
#include <stdlib.h>

#include <windows.h>
#pragma warning(push)
#pragma warning(disable:4189)
#pragma warning(disable:4091)
#include <imagehlp.h>
#pragma warning(pop)

#include <map>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include "pdbparser.h"

using namespace std;

typedef unordered_set<UINT64> ADDRESSES;
typedef map<DWORD, ADDRESSES> LINE_TO_ADDRESSES;
typedef unordered_map<string, LINE_TO_ADDRESSES> FILES;

struct LINE_INFO
{
    FILES Files;
};

static BOOL CALLBACK EnumLinesCb(
    _In_ PSRCCODEINFO LineInfo,
    _In_ PVOID UserContext
)
{
    LINE_INFO *OurLineInfo = static_cast<LINE_INFO*>(UserContext);

    std::string File = LineInfo->FileName;
    DWORD Line = LineInfo->LineNumber;

    OurLineInfo->Files[File][Line].insert(LineInfo->Address);
    return TRUE;
}

template <typename T>
static VOID PrintArray(const T &Array)
{
    unsigned Index = 0;

    printf("[");

    for (auto it : Array) {
        printf("%llu", it);

        if (Index < Array.size() - 1) {
            printf(", ");
        }

        ++Index;
    }

    printf("]");
}

static VOID PrintJson(const LINE_INFO &LineInfo)
{
    unsigned FileIndex = 0;

    printf("{\n");

    for (auto it : LineInfo.Files) {
        auto Path = JsonEscapeString(it.first);
        auto &File = it.second;

        printf("  \"%s\":[\n", Path.c_str());

        unsigned LineIndex = 0;

        for (auto lit : File) {
            auto Line = lit.first;
            auto Addresses = lit.second;

            printf("    [%d, ", Line);
            PrintArray(Addresses);
            printf("]");

            if (LineIndex == File.size() - 1) {
                printf("\n");
            } else {
                printf(",\n");
            }

            ++LineIndex;
        }

        if (FileIndex == LineInfo.Files.size() - 1) {
            printf("  ]\n");
        } else {
            printf("  ],\n");
        }

        ++FileIndex;
    }

    printf("}\n");
}

VOID DumpLineInfo(HANDLE hProcess, ULONG64 Base)
{
    LINE_INFO LineInfo;
    SymEnumSourceLines(hProcess, Base, nullptr, nullptr, 0, 0, EnumLinesCb, &LineInfo);
    PrintJson(LineInfo);
}

static VOID AddrToLine(HANDLE Process, const std::vector<UINT64> &Addresses)
{
    for (UINT i = 0; i < Addresses.size(); ++i) {
        DWORD Displacement;
        IMAGEHLP_LINE64 Line;
        if (SymGetLineFromAddr64(Process, Addresses[i], &Displacement, &Line)) {
            printf("[%d] %llx, %s:%d\n", i, Addresses[i], Line.FileName, Line.LineNumber);
        } else {
            printf("[%d] %llx Unknown address\n", i, Addresses[i]);
        }
    }
}

static VOID SplitAddresses(const std::string &String, std::vector<UINT64> &Addresses)
{
    std::istringstream is(String);
    string AddressStr;
    while (getline(is, AddressStr, '_')) {
        UINT64 Address = strtoll(AddressStr.c_str(), nullptr, 16);
        Addresses.push_back(Address);
    }
}

VOID AddrToLine(HANDLE Process, const std::string &AddressesStr)
{
    std::vector<UINT64> Addresses;
    SplitAddresses(AddressesStr, Addresses);
    AddrToLine(Process, Addresses);
}
