///
/// Copyright (C) 2014-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _S2E_LOG_H_

#define _S2E_LOG_H_

#include <s2e/s2e.h>

#define LOG(x, ...) S2EMessageFmt("s2e.sys: " ## x, __VA_ARGS__)

#endif
