///
/// Copyright (C) 2014-2017, Cyberhaven
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <stdio.h>
#include <stdlib.h>

#include <windows.h>
#include <imagehlp.h>

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

BOOL GetTypeMembers(HANDLE hProcess, ULONG64 ModuleBase,
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

    if (!SymGetTypeFromName(hProcess, ModuleBase, SymbolName.c_str(), &SymbolInfo)) {
        fprintf(stderr, "Could not get symbol info for %s (%d)\n", SymbolName.c_str(), GetLastError());
        goto err1;
    }

    if (!SymGetTypeInfo(hProcess, ModuleBase, SymbolInfo.TypeIndex, TI_GET_CHILDRENCOUNT, &ChildrenCount)) {
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

    if (!SymGetTypeInfo(hProcess, ModuleBase, SymbolInfo.TypeIndex, TI_FINDCHILDREN, Children)) {
        free(Children);
        fprintf(stderr, "Could not read children for %s (%d)\n", SymbolName.c_str(), GetLastError());
        goto err1;
    }

    for (i = 0; i < ChildrenCount; ++i) {
        symbol_t Symbol;

        WCHAR *Name;
        DWORD Offset = 0;

        SymGetTypeInfo(hProcess, ModuleBase, Children->ChildId[i], TI_GET_SYMNAME, &Name);
        SymGetTypeInfo(hProcess, ModuleBase, Children->ChildId[i], TI_GET_OFFSET, &Offset);

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

BOOL ComputeOffset(HANDLE hProcess, ULONG64 ModuleBase,
    const std::string &TypeName, const std::wstring &TypeMember,
    ULONG *Offset)
{
    TypeMembers Members;
    if (!GetTypeMembers(hProcess, ModuleBase, TypeName, Members)) {
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
    printf("   pdbparser [-f function | -t type | -i | -s | -l] file.exe file.pdb\n");
}

static BOOL GetImageInfo(const char *FileName, ULONG64 *LoadBase, DWORD *CheckSum, BOOL *Is64)
{
    FILE *fp;
    BOOL Ret = FALSE;
    IMAGE_DOS_HEADER Header;

    union
    {
        IMAGE_NT_HEADERS32 Headers32;
        IMAGE_NT_HEADERS64 Headers64;
    } Headers;

    fp = fopen(FileName, "rb");
    if (!fp) {
        fprintf(stderr, "Could not open %s\n", FileName);
        goto err0;
    }

    if (fread(&Header, sizeof(Header), 1, fp) != 1) {
        fprintf(stderr, "Could not read DOS header for %s\n", FileName);
        goto err1;
    }

    if (Header.e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "Incorrect magic for %s\n", FileName);
        goto err1;
    }

    if (fseek(fp, Header.e_lfanew, SEEK_SET) < 0) {
        fprintf(stderr, "Could not seek to NT header %s\n", FileName);
        goto err1;
    }

    if (fread(&Headers.Headers64, sizeof(Headers.Headers64), 1, fp) != 1) {
        fprintf(stderr, "Could not read NT headers for %s\n", FileName);
        goto err1;
    }

    switch (Headers.Headers32.FileHeader.Machine) {
        case IMAGE_FILE_MACHINE_I386: {
            *LoadBase = Headers.Headers32.OptionalHeader.ImageBase;
            *CheckSum = Headers.Headers32.OptionalHeader.CheckSum;
            *Is64 = FALSE;
        }
            break;
        case IMAGE_FILE_MACHINE_AMD64: {
            *LoadBase = Headers.Headers64.OptionalHeader.ImageBase;
            *CheckSum = Headers.Headers64.OptionalHeader.CheckSum;
            *Is64 = TRUE;
        }
            break;

        default: {
            fprintf(stderr, "Unsupported architecture %x for %s\n", Headers.Headers32.FileHeader.Machine, FileName);
            goto err1;
        }
    }

    Ret = TRUE;

err1: fclose(fp);
err0: return Ret;
}

bool GetSymbolAddress(HANDLE hProcess, ULONG64 ModuleBase, const char *SymbolName, UINT64 *address)
{
    g_printSymbolAddress = FALSE;
    g_symbolAddress = -1;
    SymEnumSymbols(hProcess, ModuleBase, SymbolName, EnumSymbolsCallback, NULL);
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

void InitializeSymbolMap(HANDLE hProcess, ULONG64 ModuleBase)
{
    SymEnumSymbols(hProcess, ModuleBase, "*!*", EnumInitSymbolsCallback, NULL);
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


int main(int argc, char **argv)
{
    int Ret = -1;
    HANDLE hProcess;
    const char *PdbFileName;
    const char *ExeFileName;
    const char *SymbolName;
    const char *Action;
    DWORD PdbSize;
    DWORD CheckSum;
    BOOL Is64;
    ULONG64 ModuleBase;
    ULONG64 NativeLoadBase;

    if (argc < 2) {
        Usage();
        goto err0;
    }

    Action = argv[1];
    int nextArg = 2;

    if (!strcmp(Action, "-f")) {
        SymbolName = argv[nextArg++];
        if (argc != 5) {
            Usage();
            goto err0;
        }
    } else if (!strcmp(Action, "-t")) {
        SymbolName = argv[nextArg++];
        if (argc != 5) {
            Usage();
            goto err0;
        }
    } else if (argc != 4) {
        Usage();
        goto err0;
    }

    ExeFileName = argv[nextArg++];
    PdbFileName = argv[nextArg++];

    hProcess = GetCurrentProcess();

    if (!SymInitialize(hProcess, NULL, FALSE)) {
        fprintf(stderr, "SymInitialize returned error : %d\n", GetLastError());
        goto err0;
    }

    if (!OurGetFileSize(PdbFileName, &PdbSize)) {
        fprintf(stderr, "Could not get size of %s (error %d)\n", PdbFileName, GetLastError());
        goto err1;
    }

    if (!GetImageInfo(ExeFileName, &NativeLoadBase, &CheckSum, &Is64)) {
        fprintf(stderr, "Could not get native load base of %s (error %d)\n", ExeFileName, GetLastError());
        goto err1;
    }

    //printf("Native load base: %llx Size:%d\n", NativeLoadBase, PdbSize);

    ModuleBase = SymLoadModuleEx(hProcess, NULL, PdbFileName, NULL, NativeLoadBase, PdbSize, NULL, 0);
    if (!ModuleBase) {
        fprintf(stderr, "SymLoadModuleEx returned error : %d (%s)\n", GetLastError(), PdbFileName);
        goto err1;
    }

    if (!strcmp(Action, "-f")) {
        SymEnumSymbols(hProcess, ModuleBase, SymbolName, EnumSymbolsCallback, NULL);
    }
    if (!strcmp(Action, "-l")) {
        DumpLineInfo(hProcess, ModuleBase);
    } else if (!strcmp(Action, "-t")) {
        ULONG Offset = 0;
        TypePath Path;
        std::string SymNameStr = SymbolName;
        std::string::size_type pos = SymNameStr.find(':');
        if (pos != std::string::npos) {
            std::string TypeName = std::string(SymNameStr.begin(), SymNameStr.begin() + pos);
            std::wstring MemberName = std::wstring(SymNameStr.begin() + pos + 1, SymNameStr.end());

            //printf("Looking for %s:%S\n", TypeName.c_str(), MemberName.c_str());
            if (ComputeOffset(hProcess, ModuleBase, TypeName, MemberName, &Offset)) {
                printf("%s offset %#x\n", SymbolName, Offset);
            } else {
                fprintf(stderr, "Could not find %s\n", SymbolName);
            }
        }

        //TypeMembers Members;
        //GetTypeMembers(hProcess, ModuleBase, SymbolName, Members);
    } else if (!strcmp(Action, "-i")) {
        printf("%#x %d %#llx\n", CheckSum, Is64 ? 64 : 32, ModuleBase);
    } else if (!strcmp(Action, "-s")) {
        /* Print the syscall table */
        /* 1. look for the syscall table boundary */
        UINT64 KiServiceTable, KiServiceLimit;

        if (!GetSymbolAddress(hProcess, ModuleBase, "KiServiceTable", &KiServiceTable)) {
            fprintf(stderr, "Could not find KiServiceTable\n");
            goto err2;
        }

        if (!GetSymbolAddress(hProcess, ModuleBase, "KiServiceLimit", &KiServiceLimit)) {
            fprintf(stderr, "Could not find KiServiceLimit\n");
            goto err2;
        }

        InitializeSymbolMap(hProcess, ModuleBase);

        UINT64 PtrSize = Is64 ? 8 : 4;

        /* 2. Load the image */
        PLOADED_IMAGE Img = ImageLoad((PSTR)ExeFileName, NULL);
        if (!Img) {
            fprintf(stderr, "Could not load image\n");
            goto err2;
        }

        UINT32 SyscallCount;
        if (!ReadPe(Img, NativeLoadBase, KiServiceLimit, &SyscallCount)) {
            fprintf(stderr, "Could not ready syscall count\n");
            goto err2;
        }

        /* 3. Read the array of syscall pointers */
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
                goto err2;
            }
        }

        ImageUnload(Img);
    } else {
        fprintf(stderr, "Unknown action %s\n", Action);
    }

    Ret = 0;
err2:
    SymUnloadModule64(hProcess, ModuleBase);
err1: SymCleanup(hProcess);
err0: return Ret;
}
