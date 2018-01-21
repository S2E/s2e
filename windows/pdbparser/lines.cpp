///
/// Copyright (C) 2018, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
#include <unordered_map>
#include <sstream>

#include "pdbparser.h"

using namespace std;

struct LINE_DATA
{
    std::string File;
    DWORD Line;
    UINT64 Address;
};

struct FILE_LINE_DATA
{
    DWORD Line;
    UINT64 Address;
};

typedef map<DWORD, UINT64> LINE_TO_ADDRESS;
typedef unordered_map<string, LINE_TO_ADDRESS> FILES;

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
    LINE_DATA Data;

    Data.File = LineInfo->FileName;
    Data.Line = LineInfo->LineNumber;
    Data.Address = LineInfo->Address;

    OurLineInfo->Files[Data.File][Data.Line] = Data.Address;
    return TRUE;
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
            auto Address = lit.second;

            printf("    [%d, %#llu]", Line, Address);

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
