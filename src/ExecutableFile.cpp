///
/// Copyright (C) 2012-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <vmi/DecreeFile.h>
#include <vmi/ELFFile.h>
#include <vmi/PEFile.h>

namespace vmi {

ExecutableFile::ExecutableFile(FileProvider *file, bool loaded, uint64_t loadAddress)
    : m_file(file), m_loaded(loaded), m_loadAddress(loadAddress) {
}

ExecutableFile::~ExecutableFile() {
}

ExecutableFile *ExecutableFile::get(FileProvider *file, bool loaded, uint64_t loadAddress) {
    ExecutableFile *ret;

    ret = PEFile::get(file, loaded, loadAddress);
    if (ret) {
        return ret;
    }

    ret = DecreeFile::get(file, loaded, loadAddress);
    if (ret) {
        return ret;
    }

    ret = ELFFile32::get(file, loaded, loadAddress);
    if (ret) {
        return ret;
    }

    ret = ELFFile64::get(file, loaded, loadAddress);
    if (ret) {
        return ret;
    }

    return nullptr;
}
}
