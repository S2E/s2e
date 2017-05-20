///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef __S2E_CTL__

#define __S2E_CTL__

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

#endif
