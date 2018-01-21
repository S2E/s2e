///
/// Copyright (C) 2018, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#pragma once

#include <windows.h>
#include <string>

VOID DumpLineInfo(HANDLE hProcess, ULONG64 Base);
std::string JsonEscapeString(const std::string String);
VOID AddrToLine(HANDLE Process, const std::string &AddressesStr);