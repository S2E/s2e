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

#include <stdio.h>

#include <string>
#include <map>
#include <unordered_map>

#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>

#include "pdbparser.h"

static BOOL CALLBACK EnumInitSymbolsCallback(
    PSYMBOL_INFO pSymInfo,
    ULONG SymbolSize,
    PVOID UserContext)
{
    auto &Symbols = *reinterpret_cast<SymbolInfo*>(UserContext);
    Symbols.ByAddress[pSymInfo->Address] = pSymInfo->Name;
    Symbols.ByName[pSymInfo->Name] = pSymInfo->Address;
    return TRUE;
}

BOOL GetSymbolMap(SymbolInfo &Symbols, HANDLE Process, ULONG64 ModuleBase)
{
    return SymEnumSymbols(Process, ModuleBase, "*!*", EnumInitSymbolsCallback, &Symbols);
}

void DumpSymbolMapAsJson(const SymbolInfo &Symbols, rapidjson::Document &Doc)
{
    std::unordered_map<std::string, uint64_t> NameToAddr;
    auto &Allocator = Doc.GetAllocator();

    rapidjson::Value CUValue(rapidjson::kObjectType);

    for (const auto &it : Symbols.ByName) {
        rapidjson::Value Name(rapidjson::kStringType), Address;
        Name.SetString(it.first.c_str(), Allocator);
        Address.SetUint64(it.second);
        CUValue.AddMember(Name, Address, Allocator);
    }

    Doc.AddMember("symbols", CUValue, Allocator);
}
