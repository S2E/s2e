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

    Status = RtlStringCchLengthA(String, MaxInputLen, &Len);
    if (!NT_SUCCESS(Status)) {
        LOG("Could not get string length\n");
        goto err;
    }

    Buffer = ExAllocatePoolWithTag(NonPagedPool, MaxInputLen * sizeof(WCHAR), TAG_STR);
    if (!Buffer) {
        LOG("Could not allocate buffer for string\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto err;
    }

    Unicode->Buffer = Buffer;
    Unicode->MaximumLength = (USHORT)(MaxInputLen * sizeof(WCHAR));
    Unicode->Length = (USHORT)(Len * sizeof(USHORT));

    for (unsigned i = 0; i < Unicode->Length; ++i) {
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
    Dest->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, Source->MaximumLength, 0xdead);
    if (!Dest->Buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(Dest->Buffer, Source->Buffer, Source->MaximumLength);

    return STATUS_SUCCESS;
}
