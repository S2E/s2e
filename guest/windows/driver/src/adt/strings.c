///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
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

#include <ntddk.h>
#include <ntstrsafe.h>
#include "../log.h"
#include "strings.h"

#define TAG_STR 'stri'

NTSTATUS StringToUnicode(_In_ LPCSTR String, _In_ SIZE_T MaxInputLen, _Out_ PUNICODE_STRING Unicode)
{
    NTSTATUS Status;
    size_t Len;
    PVOID Buffer;
    size_t BufferSize;

    Status = RtlStringCchLengthA(String, MaxInputLen, &Len);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not get string length\n");
        goto err;
    }

    BufferSize = Len * sizeof(WCHAR);
    if (BufferSize > 65534) {
        Status = STATUS_BUFFER_OVERFLOW;
        goto err;
    }

    Buffer = ExAllocatePoolWithTag(NonPagedPoolNx, BufferSize, TAG_STR);
    if (!Buffer) {
        LOG("Could not allocate buffer for string\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto err;
    }

    Unicode->Buffer = Buffer;
    Unicode->MaximumLength = (USHORT) BufferSize;
    Unicode->Length = (USHORT) BufferSize;

    for (unsigned i = 0; i < BufferSize / sizeof(WCHAR); ++i) {
        Unicode->Buffer[i] = String[i];
    }

    Status = STATUS_SUCCESS;

err:
    return Status;
}

VOID StringFree(_Inout_ PUNICODE_STRING String)
{
    if (String->Buffer) {
        ExFreePoolWithTag(String->Buffer, TAG_STR);
    }

    String->Buffer = NULL;
    String->MaximumLength = 0;
    String->Length = 0;
}

NTSTATUS StringDuplicate(_Out_ PUNICODE_STRING Dest, _In_ PCUNICODE_STRING Source)
{
    *Dest = *Source;
    Dest->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPoolNx, Source->MaximumLength, TAG_STR);
    if (!Dest->Buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(Dest->Buffer, Source->Buffer, Source->MaximumLength);

    return STATUS_SUCCESS;
}

PSTR StringDuplicateA(_In_ PCSTR Source, _In_ SIZE_T Size)
{
    PSTR Ret;
    Ret = (PSTR)ExAllocatePoolWithTag(NonPagedPoolNx, Size, TAG_STR);
    if (!Ret) {
        return NULL;
    }

    memcpy(Ret, Source, Size);

    return Ret;
}

PCHAR StringCat(_In_opt_ PCCHAR Str1, _In_opt_ PCCHAR Str2)
{
    PCHAR Ret = NULL;
    size_t Len1 = Str1 ? strlen(Str1) : 0;
    size_t Len2 = Str2 ? strlen(Str2) : 0;
    size_t ToAllocate = Len1 + Len2 + 1;

    Ret = ExAllocatePoolWithTag(NonPagedPoolNx, ToAllocate, TAG_STR);
    if (!Ret) {
        return NULL;
    }

    if (Str1) {
        memcpy(Ret, Str1, Len1);
    }

    if (Str2) {
        memcpy(Ret + Len1, Str2, Len2);
    }

    Ret[ToAllocate - 1] = 0;

    return Ret;
}

NTSTATUS StringCatInPlace(_Inout_ PCCHAR *Str1, _In_ PCCHAR Str2)
{
    PCHAR NewBuffer = StringCat(*Str1, Str2);
    if (!NewBuffer) {
        LOG("Could not allocate buffer");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (*Str1) {
        ExFreePoolWithTag(*Str1, TAG_STR);
    }

    *Str1 = NewBuffer;

    return STATUS_SUCCESS;
}

NTSTATUS StringAllocateUnicode(_Inout_ PUNICODE_STRING String)
{
    NTSTATUS Status = STATUS_INVALID_PARAMETER;

    if (!String) {
        goto err;
    }

    String->Buffer = 0;
    String->Length = 0;

    if (!(String->MaximumLength >= sizeof(WCHAR))) {
        goto err;
    }

    String->Buffer = ExAllocatePoolWithTag(NonPagedPoolNx, String->MaximumLength, TAG_STR);
    if (String->Buffer == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto err;
    }

    Status = STATUS_SUCCESS;

err:
    return Status;
}
