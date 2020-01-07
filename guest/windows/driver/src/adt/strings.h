///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#pragma once

NTSTATUS StringToUnicode(_In_ LPCSTR String, _In_ SIZE_T MaxInputLen, _Out_ PUNICODE_STRING Unicode);
VOID StringFree(_Inout_ PUNICODE_STRING String);
NTSTATUS StringDuplicate(_Out_ PUNICODE_STRING Dest, _In_ PCUNICODE_STRING Source);
PSTR StringDuplicateA(_In_ PCSTR Source, _In_ SIZE_T Size);
PCHAR StringCat(_In_opt_ PCCHAR Str1, _In_opt_ PCCHAR Str2);
NTSTATUS StringCatInPlace(_Inout_ PCCHAR *Str1, _In_ PCCHAR Str2);
NTSTATUS StringAllocateUnicode(_Inout_ PUNICODE_STRING String);
