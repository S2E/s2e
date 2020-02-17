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

#include <windows.h>

#pragma warning(push)
#pragma warning(disable:4189)
#pragma warning(disable:4091)
#include <imagehlp.h>
#pragma warning(pop)

#include <map>
#include <vector>
#include <xstring>

#include "pdbparser.h"

struct symbol_t
{
    unsigned offset;
    ULONG64 length;
    unsigned child_id;
    unsigned type_id;
    std::wstring name;
};

typedef std::vector<symbol_t> TypeMembers;
typedef std::vector<std::wstring> TypePath;

BOOL GetTypeMembers(HANDLE Process, ULONG64 ModuleBase,
    const std::string &SymbolName,
    TypeMembers &Members)
{
    SYMBOL_INFO SymbolInfo;
    DWORD ChildrenCount, ChildrenSize;
    TI_FINDCHILDREN_PARAMS *Children;
    DWORD i;
    BOOL Ret = FALSE;

    memset(&SymbolInfo, 0, sizeof(SymbolInfo));
    SymbolInfo.SizeOfStruct = sizeof(SymbolInfo);

    if (!SymGetTypeFromName(Process, ModuleBase, SymbolName.c_str(), &SymbolInfo)) {
        fprintf(stderr, "Could not get symbol info for %s (%d)\n", SymbolName.c_str(), GetLastError());
        goto err1;
    }

    if (!SymGetTypeInfo(Process, ModuleBase, SymbolInfo.TypeIndex, TI_GET_CHILDRENCOUNT, &ChildrenCount)) {
        fprintf(stderr, "Could not get children count for %s (%d)\n", SymbolName.c_str(), GetLastError());
        goto err1;
    }

    //printf("Type %s has %d children\n", SymbolName.c_str(), ChildrenCount);

    ChildrenSize = sizeof(*Children) + ChildrenCount * sizeof(ULONG);
    Children = (TI_FINDCHILDREN_PARAMS*)malloc(ChildrenSize);
    if (!Children) {
        fprintf(stderr, "Could not allocate memory for children of %s (%d)\n", SymbolName.c_str(), GetLastError());
        goto err1;
    }

    memset(Children, 0, ChildrenSize);
    Children->Start = 0;
    Children->Count = ChildrenCount;

    if (!SymGetTypeInfo(Process, ModuleBase, SymbolInfo.TypeIndex, TI_FINDCHILDREN, Children)) {
        free(Children);
        fprintf(stderr, "Could not read children for %s (%d)\n", SymbolName.c_str(), GetLastError());
        goto err1;
    }

    for (i = 0; i < ChildrenCount; ++i) {
        symbol_t Symbol;

        WCHAR *Name;
        DWORD Offset = 0;

        SymGetTypeInfo(Process, ModuleBase, Children->ChildId[i], TI_GET_SYMNAME, &Name);
        SymGetTypeInfo(Process, ModuleBase, Children->ChildId[i], TI_GET_OFFSET, &Offset);

        Symbol.child_id = Children->ChildId[i];
        Symbol.offset = Offset;
        Symbol.name = Name;
        Members.push_back(Symbol);

        LocalFree(Name);
    }

    free(Children);

    Ret = TRUE;
err1:
    return Ret;
}

BOOL ComputeOffset(HANDLE Process, ULONG64 ModuleBase,
    const std::string &TypeName, const std::wstring &TypeMember,
    ULONG *Offset)
{
    TypeMembers Members;
    if (!GetTypeMembers(Process, ModuleBase, TypeName, Members)) {
        return FALSE;
    }

    for (TypeMembers::const_iterator it = Members.begin(); it != Members.end(); ++it) {
        const symbol_t &Symbol = (*it);
        if (Symbol.name.compare(TypeMember) != 0) {
            continue;
        }

        *Offset = Symbol.offset;

        return TRUE;
    }

    return FALSE;
}

BOOL OurGetFileSize(const char *pFileName, DWORD *pFileSize)
{
    BOOLEAN Ret = FALSE;
    HANDLE hFile = CreateFile(pFileName, GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        goto err0;
    }

    *pFileSize = GetFileSize(hFile, NULL);
    if (*pFileSize == INVALID_FILE_SIZE) {
        goto err1;
    }

    Ret = TRUE;

err1: CloseHandle(hFile);
err0: return Ret;
}

bool g_printSymbolAddress = true;
UINT64 g_symbolAddress = -1;

static BOOL CALLBACK EnumSymbolsCallback(
    PSYMBOL_INFO pSymInfo,
    ULONG SymbolSize,
    PVOID UserContext)
{
    if (g_printSymbolAddress) {
        printf("Sym %s %#llx\n", pSymInfo->Name, pSymInfo->Address);
    }

    g_symbolAddress = pSymInfo->Address;
    return TRUE;
}

static BOOL CALLBACK EnumTypesCallback(
    PSYMBOL_INFO pSymInfo,
    ULONG SymbolSize,
    PVOID UserContext)
{
    const char *SearchedName = (const char *)UserContext;

    if (strcmp(pSymInfo->Name, SearchedName)) {
        return TRUE;
    }

    printf("Type %s %#llx\n", pSymInfo->Name, pSymInfo->Address);

    return FALSE;
}

static VOID Usage(VOID)
{
    printf("Usage:\n");
    printf("   pdbparser [-f function | -t type | -a addresses | -i | -s | -l] file.exe file.pdb\n");
}

_Success_(return)
static BOOL GetImageInfo(
    _In_    const char *FileName,
    _Out_    ULONG64 *LoadBase,
    _Out_    DWORD *CheckSum,
    _Out_    bool *Is64
)
{
    FILE *fp = nullptr;
    BOOL Ret = FALSE;
    IMAGE_DOS_HEADER Header;

    union
    {
        IMAGE_NT_HEADERS32 Headers32;
        IMAGE_NT_HEADERS64 Headers64;
    } Headers;

    if (fopen_s(&fp, FileName, "rb") || !fp) {
        fprintf(stderr, "Could not open %s\n", FileName);
        goto err;
    }

    if (fread(&Header, sizeof(Header), 1, fp) != 1) {
        fprintf(stderr, "Could not read DOS header for %s\n", FileName);
        goto err;
    }

    if (Header.e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "Incorrect magic for %s\n", FileName);
        goto err;
    }

    if (fseek(fp, Header.e_lfanew, SEEK_SET) < 0) {
        fprintf(stderr, "Could not seek to NT header %s\n", FileName);
        goto err;
    }

    if (fread(&Headers.Headers64, sizeof(Headers.Headers64), 1, fp) != 1) {
        fprintf(stderr, "Could not read NT headers for %s\n", FileName);
        goto err;
    }

    switch (Headers.Headers32.FileHeader.Machine) {
        case IMAGE_FILE_MACHINE_I386: {
            *LoadBase = Headers.Headers32.OptionalHeader.ImageBase;
            *CheckSum = Headers.Headers32.OptionalHeader.CheckSum;
            *Is64 = false;
        }
            break;
        case IMAGE_FILE_MACHINE_AMD64: {
            *LoadBase = Headers.Headers64.OptionalHeader.ImageBase;
            *CheckSum = Headers.Headers64.OptionalHeader.CheckSum;
            *Is64 = true;
        }
            break;

        default: {
            fprintf(stderr, "Unsupported architecture %x for %s\n", Headers.Headers32.FileHeader.Machine, FileName);
            goto err;
        }
    }

    Ret = TRUE;

err:
    if (fp) {
        fclose(fp);
    }

    return Ret;
}

bool GetSymbolAddress(HANDLE Process, ULONG64 ModuleBase, const char *SymbolName, UINT64 *address)
{
    g_printSymbolAddress = FALSE;
    g_symbolAddress = -1;
    SymEnumSymbols(Process, ModuleBase, SymbolName, EnumSymbolsCallback, NULL);
    if (g_symbolAddress == -1) {
        fprintf(stderr, "Could not find %s\n", SymbolName);
        return false;
    }

    *address = g_symbolAddress;
    return true;
}

static std::map<UINT64, std::string> g_symbolMap;

static BOOL CALLBACK EnumInitSymbolsCallback(
    PSYMBOL_INFO pSymInfo,
    ULONG SymbolSize,
    PVOID UserContext)
{
    g_symbolMap[pSymInfo->Address] = pSymInfo->Name;
    return TRUE;
}

void InitializeSymbolMap(HANDLE Process, ULONG64 ModuleBase)
{
    SymEnumSymbols(Process, ModuleBase, "*!*", EnumInitSymbolsCallback, NULL);
}

template <typename T>
bool ReadPe(PLOADED_IMAGE Image, UINT64 NativeLoadBase, UINT64 NativeAddress, T *ret)
{
    for (unsigned i = 0; i < Image->NumberOfSections; ++i) {
        DWORD SVA = Image->Sections[i].VirtualAddress;
        DWORD SSize = Image->Sections[i].SizeOfRawData;
        if (NativeAddress >= SVA + NativeLoadBase && NativeAddress + sizeof(T) <= SVA + NativeLoadBase + SSize) {
            DWORD Offset = (DWORD)((NativeAddress - NativeLoadBase) - Image->Sections[i].VirtualAddress);
            Offset += Image->Sections[i].PointerToRawData;
            *ret = *(T*)(Image->MappedAddress + Offset);
            return true;
        }
    }

    return false;
}

static void DumpTypeOffset(HANDLE Process, ULONG64 ModuleBase, const std::string &SymbolName)
{
    ULONG Offset = 0;
    TypePath Path;

    std::string::size_type pos = SymbolName.find(':');
    if (pos != std::string::npos) {
        std::string TypeName = std::string(SymbolName.begin(), SymbolName.begin() + pos);
        std::wstring MemberName = std::wstring(SymbolName.begin() + pos + 1, SymbolName.end());

        //printf("Looking for %s:%S\n", TypeName.c_str(), MemberName.c_str());
        if (ComputeOffset(Process, ModuleBase, TypeName, MemberName, &Offset)) {
            printf("%s offset %#x\n", SymbolName.c_str(), Offset);
        } else {
            fprintf(stderr, "Could not find %s\n", SymbolName.c_str());
        }
    }

    //TypeMembers Members;
    //GetTypeMembers(Process, ModuleBase, SymbolName, Members);
}

// Print the syscall table
static void DumpSyscalls(HANDLE Process, const std::string &ImagePath, ULONG64 ModuleBase, UINT64 NativeLoadBase,
    bool Is64)
{
    PLOADED_IMAGE Img = nullptr;

    // 1. look for the syscall table boundary
    UINT64 KiServiceTable, KiServiceLimit;

    if (!GetSymbolAddress(Process, ModuleBase, "KiServiceTable", &KiServiceTable)) {
        fprintf(stderr, "Could not find KiServiceTable\n");
        goto err;
    }

    if (!GetSymbolAddress(Process, ModuleBase, "KiServiceLimit", &KiServiceLimit)) {
        fprintf(stderr, "Could not find KiServiceLimit\n");
        goto err;
    }

    InitializeSymbolMap(Process, ModuleBase);

    UINT64 PtrSize = Is64 ? 8 : 4;

    // 2. Load the image
    Img = ImageLoad((PSTR)ImagePath.c_str(), NULL);
    if (!Img) {
        fprintf(stderr, "Could not load image\n");
        goto err;
    }

    UINT32 SyscallCount;
    if (!ReadPe(Img, NativeLoadBase, KiServiceLimit, &SyscallCount)) {
        fprintf(stderr, "Could not ready syscall count\n");
        goto err;
    }

    // 3. Read the array of syscall pointers
    UINT64 *SyscallPtrs = new UINT64[SyscallCount];
    for (UINT i = 0; i < SyscallCount; ++i) {
        bool Result;

        if (Is64) {
            UINT32 Ret;
            Result = ReadPe(Img, NativeLoadBase, KiServiceTable + i * sizeof(UINT32), &Ret);
            SyscallPtrs[i] = NativeLoadBase + Ret;
        } else {
            UINT32 Ret;
            Result = ReadPe(Img, NativeLoadBase, KiServiceTable + i * sizeof(UINT32), &Ret);
            SyscallPtrs[i] = Ret;
        }

        const std::string &symbolName = g_symbolMap[SyscallPtrs[i]];
        printf("%d %#llx %s\n", i, SyscallPtrs[i], symbolName.c_str());

        if (!Result) {
            printf("Syscall extraction failed\n");
            goto err;
        }
    }

err:
    if (Img) {
        ImageUnload(Img);
    }
}

enum ACTION
{
    ENUM_SYMBOLS,
    DUMP_LINE_INFO,
    ADDR_TO_LINE,
    DUMP_TYPE,
    DUMP_PE_INFO,
    DUMP_SYSCALLS
};

struct ARGUMENTS
{
    ACTION Action;
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
        case 'f':
            Args.Action = ENUM_SYMBOLS;
            destArg = &Args.SymbolName;
            break;
        case 't':
            Args.Action = DUMP_TYPE;
            destArg = &Args.SymbolName;
            break;
        case 'a':
            Args.Action = ADDR_TO_LINE;
            destArg = &Args.Addresses;
            break;
        case 'l':
            Args.Action = DUMP_LINE_INFO;
            break;
        case 'i':
            Args.Action = DUMP_PE_INFO;
            break;
        case 's':
            Args.Action = DUMP_SYSCALLS;
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

    switch (Args.Action) {
        case ENUM_SYMBOLS:
            SymEnumSymbols(Process, ModuleBase, Args.SymbolName.c_str(), EnumSymbolsCallback, NULL);
            break;
        case DUMP_LINE_INFO:
            DumpLineInfo(Process, ModuleBase);
            break;
        case ADDR_TO_LINE:
            AddrToLine(Process, Args.Addresses);
            break;
        case DUMP_TYPE:
            DumpTypeOffset(Process, ModuleBase, Args.SymbolName);
            break;
        case DUMP_PE_INFO:
            printf("%#x %d %#llx\n", CheckSum, Is64 ? 64 : 32, ModuleBase);
            break;
        case DUMP_SYSCALLS:
            DumpSyscalls(Process, Args.ExeFileName, ModuleBase, NativeLoadBase, Is64);
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
