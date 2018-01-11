///
/// Copyright (C) 2018, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <stdio.h>
#include <stdlib.h>

#include <windows.h>
#include <imagehlp.h>

#include <map>
#include <unordered_map>

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
