///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2018, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef __S2E_CTL__

#define __S2E_CTL__

#if defined(USER_APP)
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#endif

#define FSCTL_S2E_BASE      FILE_DEVICE_UNKNOWN

#define _S2E_CTL_CODE(_Function, _Method, _Access)  \
            CTL_CODE(FSCTL_S2E_BASE, _Function, _Method, _Access)

#define IOCTL_S2E_REGISTER_MODULE   \
            _S2E_CTL_CODE(0x200, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_S2E_CUSTOM_BUG   \
            _S2E_CTL_CODE(0x201, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_S2E_WINDOWS_USERMODE_CRASH   \
            _S2E_CTL_CODE(0x202, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_S2E_CRASH_KERNEL   \
            _S2E_CTL_CODE(0x203, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_S2E_SET_CONFIG   \
            _S2E_CTL_CODE(0x204, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#pragma warning(push)
#pragma warning(disable: 4200)
typedef struct
{
    // Total size of this structure (in bytes)
    UINT64 Size;

    UINT64 Value;

    // ASCIIZ string
    CHAR Name[];
} S2E_IOCTL_SET_CONFIG;
#pragma warning(pop)

#if defined(USER_APP)
static S2E_IOCTL_SET_CONFIG *S2ESerializeIoctlSetConfig(LPCSTR Name, UINT64 Value)
{
    size_t NameSize = strlen(Name) + 1;
    size_t Length = sizeof(S2E_IOCTL_SET_CONFIG) + NameSize;
    S2E_IOCTL_SET_CONFIG *Ret = (S2E_IOCTL_SET_CONFIG*) malloc(Length);
    if (!Ret) {
        return NULL;
    }

    Ret->Size = Length;
    Ret->Value = Value;
    memcpy(Ret->Name, Name, NameSize);
    return Ret;
}

static BOOL S2EIoctlSetConfig(HANDLE Driver, LPCSTR Name, UINT64 Value)
{
    S2E_IOCTL_SET_CONFIG *Cfg = S2ESerializeIoctlSetConfig(Name, Value);
    if (!Cfg) {
        return FALSE;
    }

    BOOL Ret = S2EIoCtl(Driver, IOCTL_S2E_SET_CONFIG, Cfg, (DWORD) Cfg->Size);

    free(Cfg);
    return Ret;
}
#endif

#endif
