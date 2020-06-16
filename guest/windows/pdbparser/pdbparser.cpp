///
/// Copyright (C) 2014-2017, Cyberhaven
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
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
#include <iostream>
#include <windows.h>
#include <xstring>

#include "pdbparser.h"

static VOID Usage(VOID)
{
    printf("Usage:\n");
    printf("   pdbparser [-a addresses | -l | -d] file.exe file.pdb\n");
}

static void PrintJson(const rapidjson::Document &Doc, rapidjson::StringBuffer &Buffer)
{
    rapidjson::PrettyWriter<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::UTF8<>>
        Writer(Buffer);
    Doc.Accept(Writer);
}

enum ACTION
{
    DUMP_INFO,
    DUMP_LINE_INFO,
    ADDR_TO_LINE,
};

struct ARGUMENTS
{
    ACTION Action = DUMP_INFO;
    std::string SymbolName;
    std::string Addresses;

    std::string PdbFileName;
    std::string ExeFileName;
};

static bool ParseArguments(ARGUMENTS &Args, int argc, char **argv)
{
    int NextArg = 1;
    bool Result = false;
    std::string Action;

    if (argc < 2) {
        goto err;
    }

    Action = argv[NextArg++];
    if (Action.size() != 2) {
        goto err;
    }

    std::string *destArg = nullptr;

    switch (Action[1]) {
        case 'd':
            Args.Action = DUMP_INFO;
            break;
        case 'a':
            Args.Action = ADDR_TO_LINE;
            destArg = &Args.Addresses;
            break;
        case 'l':
            Args.Action = DUMP_LINE_INFO;
            break;
        default:
            goto err;
    }

    if (destArg) {
        if (NextArg >= argc) {
            goto err;
        }
        *destArg = argv[NextArg++];
    }

    if (NextArg >= argc) {
        goto err;
    }
    Args.ExeFileName = argv[NextArg++];

    if (NextArg >= argc) {
        goto err;
    }
    Args.PdbFileName = argv[NextArg++];

    Result = true;

err:
    return Result;
}

void DumpPeInfoAsJson(rapidjson::Document &Doc, UINT32 Checksum, UINT32 Bits, UINT64 NativeBase)
{
    auto &Allocator = Doc.GetAllocator();
    rapidjson::Value JsonInfo(rapidjson::kObjectType);

    JsonInfo.AddMember("checksum", Checksum, Allocator);
    JsonInfo.AddMember("bits", Bits, Allocator);
    JsonInfo.AddMember("native_base", NativeBase, Allocator);

    Doc.AddMember("info", JsonInfo, Allocator);
}

int main(int argc, char **argv)
{
    int Ret = -1;
    ARGUMENTS Args;
    bool SymInited = false;
    bool ModuleLoaded = false;

    HANDLE Process;
    DWORD PdbSize;
    DWORD CheckSum;
    bool Is64;
    ULONG64 ModuleBase;
    ULONG64 NativeLoadBase;

    SymbolInfo Symbols;

    if (!ParseArguments(Args, argc, argv)) {
        Usage();
        goto err;
    }

    Process = GetCurrentProcess();

    if (!SymInitialize(Process, NULL, FALSE)) {
        fprintf(stderr, "SymInitialize returned error : %d\n", GetLastError());
        goto err;
    }
    SymInited = true;

    if (!OurGetFileSize(Args.PdbFileName.c_str(), &PdbSize)) {
        fprintf(stderr, "Could not get size of %s (error %d)\n", Args.PdbFileName.c_str(), GetLastError());
        goto err;
    }

    if (!GetImageInfo(Args.ExeFileName.c_str(), &NativeLoadBase, &CheckSum, &Is64)) {
        fprintf(stderr, "Could not get native load base of %s (error %d)\n", Args.ExeFileName.c_str(), GetLastError());
        goto err;
    }

    //printf("Native load base: %llx Size:%d\n", NativeLoadBase, PdbSize);

    ModuleBase = SymLoadModuleEx(Process, NULL, Args.PdbFileName.c_str(), NULL, NativeLoadBase, PdbSize, NULL, 0);
    if (!ModuleBase) {
        fprintf(stderr, "SymLoadModuleEx returned error : %d (%s)\n", GetLastError(), Args.PdbFileName.c_str());
        goto err;
    }
    ModuleLoaded = true;

    if (!GetSymbolMap(Symbols, Process, ModuleBase)) {
        fprintf(stderr, "Could not load symbols\n");
        goto err;
    }

    switch (Args.Action) {
        case DUMP_INFO: {
            rapidjson::Document Doc;
            Doc.SetObject();
            DumpSymbolMapAsJson(Symbols, Doc);
            DumpTypesAsJson(Doc, Process, ModuleBase);

            Syscalls Sc;
            DumpSyscalls(Sc, Symbols, Process, Args.ExeFileName, ModuleBase, NativeLoadBase, Is64);
            if (Sc.size()) {
                DumpSyscallsAsJson(Doc, Sc);
            }

            DumpPeInfoAsJson(Doc, CheckSum, Is64 ? 64 : 32, ModuleBase);

            rapidjson::StringBuffer Buffer;
            PrintJson(Doc, Buffer);
            std::cout << Buffer.GetString() << "\n";
        }
        break;
        case DUMP_LINE_INFO: {
            rapidjson::Document Doc;
            Doc.SetObject();

            DumpLineInfoAsJson(Doc, Process, ModuleBase);

            rapidjson::StringBuffer Buffer;
            PrintJson(Doc, Buffer);
            std::cout << Buffer.GetString() << "\n";
        }
        break;
        case ADDR_TO_LINE:
            // TODO: integrate this with the json dump
            AddrToLine(Process, Args.Addresses);
            break;
        default:
            fprintf(stderr, "Unknown action %d\n", Args.Action);
            break;
    }

    Ret = 0;

err:
    if (ModuleLoaded) {
        SymUnloadModule64(Process, ModuleBase);
    }

    if (SymInited) {
        SymCleanup(Process);
    }

    return Ret;
}
