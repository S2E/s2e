///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _HARDENING_H_

#define _HARDENING_H_

#include <vmi/ExecutableFile.h>
#include <vmi/FileProvider.h>
#include <vmi/PEFile.h>
#include "lib/Utils/Log.h"

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/DenseSet.h>

namespace s2etools {

class Hardening {
    static LogKey TAG;

    std::string m_inputBinaryPath;
    vmi::PEFile *m_inputBinary;
    vmi::FileSystemFileProvider *m_fp;

    uint8_t *assemble(const std::string &assembly, unsigned *size);
    uint64_t getImportedFunction(const std::string &dll, const std::string &function);

public:
    Hardening(const std::string &inputBinaryPath) : m_inputBinaryPath(inputBinaryPath) {
        m_inputBinary = NULL;
        m_fp = NULL;
    }

    ~Hardening();

    bool initialize();
    bool harden(uint64_t pc);
};
}

#endif
