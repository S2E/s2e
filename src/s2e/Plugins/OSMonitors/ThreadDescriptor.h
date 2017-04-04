///
/// Copyright (C) 2012-2014, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _THREAD_DESCRIPTOR_H_

#define _THREAD_DESCRIPTOR_H_

namespace s2e {

struct ThreadDescriptor {
    uint64_t Pid;
    uint64_t Tid;
    uint64_t KernelStackBottom;
    uint64_t KernelStackSize;

    bool KernelMode;
    // TODO: add other interesting information

    ThreadDescriptor() {
        Pid = Tid = 0;
        KernelStackBottom = 0;
        KernelStackSize = 0;
        KernelMode = false;
    }
};
}

#endif
