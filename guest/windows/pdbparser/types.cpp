///
/// Copyright (C) 2014-2020, Cyberhaven
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

#include <codecvt>

#include "pdbparser.h"

static BOOL GetTypeMembers(
    HANDLE Process, ULONG64 ModuleBase,
    const std::string &SymbolName,
    TypeMembers &Members
)
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
        ULONG64 Length = 0;
        DWORD TypeId = 0;

        SymGetTypeInfo(Process, ModuleBase, Children->ChildId[i], TI_GET_SYMNAME, &Name);
        SymGetTypeInfo(Process, ModuleBase, Children->ChildId[i], TI_GET_OFFSET, &Offset);
        SymGetTypeInfo(Process, ModuleBase, Children->ChildId[i], TI_GET_TYPEID, &TypeId);
        SymGetTypeInfo(Process, ModuleBase, TypeId, TI_GET_LENGTH, &Length);

        Symbol.child_id = Children->ChildId[i];
        Symbol.offset = Offset;
        Symbol.length = Length;

        std::wstring WName = Name;
        std::wstring_convert<std::codecvt_utf8<wchar_t>> Converter;
        Symbol.name = Converter.to_bytes(WName);
        Members.push_back(Symbol);

        LocalFree(Name);
    }

    free(Children);

    Ret = TRUE;
err1:
    return Ret;
}

static BOOL CALLBACK EnumerateTypesCb(
    PSYMBOL_INFO pSymInfo,
    ULONG SymbolSize,
    PVOID UserContext
)
{
    TypeNames &Types = *reinterpret_cast<TypeNames*>(UserContext);
    if (!pSymInfo->NameLen || !pSymInfo->MaxNameLen) {
        return TRUE;
    }

    std::string TypeName(pSymInfo->Name, pSymInfo->NameLen);
    Types.insert(TypeName);
    return TRUE;
}

VOID EnumerateTypes(HANDLE Process, ULONG64 ModuleBase, TypeNames &Types)
{
    SymEnumTypes(Process, ModuleBase, EnumerateTypesCb, &Types);
}

void DumpTypesAsJson(rapidjson::Document &Doc, HANDLE Process, UINT64 ModuleBase)
{
    TypeNames Types;
    EnumerateTypes(Process, ModuleBase, Types);
    auto &Allocator = Doc.GetAllocator();

    rapidjson::Value CUValue(rapidjson::kObjectType);

    for (const auto &TypeName : Types) {
        rapidjson::Value Name(rapidjson::kStringType);
        Name.SetString(TypeName.c_str(), Allocator);

        TypeMembers Members;
        rapidjson::Value TypeInfo(rapidjson::kObjectType);
        if (GetTypeMembers(Process, ModuleBase, TypeName, Members)) {
            for (const auto &Member : Members) {
                rapidjson::Value MemberInfo(rapidjson::kObjectType);
                MemberInfo.AddMember("offset", Member.offset, Allocator);
                MemberInfo.AddMember("size", Member.length, Allocator);

                rapidjson::Value JsonMemberName(rapidjson::kStringType);
                JsonMemberName.SetString(Member.name.c_str(), Allocator);
                TypeInfo.AddMember(JsonMemberName, MemberInfo, Allocator);
            }
        }

        CUValue.AddMember(Name, TypeInfo, Allocator);
    }

    Doc.AddMember("types", CUValue, Allocator);
}
