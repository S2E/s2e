#pragma once

NTSTATUS StringToUnicode(_In_ LPCSTR String, _In_ SIZE_T MaxInputLen, _Out_ PUNICODE_STRING Unicode);
VOID StringFree(_Inout_ PUNICODE_STRING String);
NTSTATUS StringDuplicate(_Out_ PUNICODE_STRING Dest, _In_ PCUNICODE_STRING Source);
