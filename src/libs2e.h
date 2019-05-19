///
/// Copyright (C) 2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef LIBS2E_H

#define LIBS2E_H

#include "FileDescriptorManager.h"

extern s2e::kvm::FileDescriptorManagerPtr g_fdm;

struct se_libcpu_interface_t;
void init_s2e_libcpu_interface(struct se_libcpu_interface_t *sqi);

namespace s2e {
namespace kvm {
extern struct cpu_io_funcs_t g_io;
}
}

#endif
