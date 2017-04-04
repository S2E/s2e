///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "Library.h"
#include "lib/ExecutionTracer/ModuleParser.h"

#include <fstream>
#include <iostream>
#include <sstream>

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"

// XXX Move this to a better place
namespace {
llvm::cl::opt<unsigned> KernelStart("os", llvm::cl::desc("Start address of kernel space"), llvm::cl::init(0x80000000));
}

namespace s2etools {

uint64_t Library::translatePid(uint64_t pid, uint64_t pc) {
    if (pc >= KernelStart) {
        return 0;
    }

    return pid;
}

Library::~Library() {
    for (auto &library : m_libraries) {
        vmi::FileProvider *fp = library.second->get();
        delete library.second;
        delete fp;
    }
}

void Library::addPath(const std::string &path) {
    m_libpath.push_back(path);
}

void Library::setPaths(const PathList &s) {
    m_libpath.clear();
    m_libpath = s;
}

bool Library::findLibrary(const std::string &libName, std::string &abspath) {
    for (auto libpath : m_libpath) {
        llvm::SmallString<128> lib(libpath);
        llvm::sys::path::append(lib, libName);

        if (llvm::sys::fs::exists(lib)) {
            abspath = lib.str();
            return true;
        }
    }

    return false;
}

bool Library::findSuffixedModule(const std::string &moduleName, const std::string &suffix, std::string &path) {
    for (auto libpath : m_libpath) {
        llvm::SmallString<128> list(libpath);
        llvm::sys::path::append(list, moduleName);
        llvm::sys::path::replace_extension(list, suffix);

        if (llvm::sys::fs::exists(list)) {
            path = list.c_str();
            return true;
        }
    }

    return false;
}

bool Library::findBasicBlockList(const std::string &moduleName, std::string &path) {
    return findSuffixedModule(moduleName, "bblist", path);
}

bool Library::findDisassemblyListing(const std::string &moduleName, std::string &path) {
    return findSuffixedModule(moduleName, "lst", path);
}

bool Library::addLibrary(const std::string &libName) {
    std::string s;

    if (!findLibrary(libName, s)) {
        return false;
    } else {
        return addLibraryAbs(s);
    }
}

bool Library::addLibraryAbs(const std::string &libName) {
    vmi::FileProvider *fp = NULL;
    vmi::ExecutableFile *exec = NULL;

    if (m_libraries.find(libName) != m_libraries.end()) {
        return true;
    }

    if (m_badLibraries.find(libName) != m_badLibraries.end()) {
        return false;
    }

    std::string ProgFile = libName;

    fp = vmi::FileSystemFileProvider::get(ProgFile, false);
    if (!fp) {
        goto err1;
    }

    exec = vmi::ExecutableFile::get(fp, false, 0);
    if (!exec) {
        goto err1;
    }

    m_libraries[libName] = exec;

    return true;

err1:
    if (exec) {
        delete exec;
    }

    if (fp) {
        delete fp;
    }

    m_badLibraries.insert(ProgFile);
    return false;
}

vmi::ExecutableFile *Library::get(const std::string &name) {
    std::string s;
    if (!findLibrary(name, s)) {
        return NULL;
    }

    if (!addLibraryAbs(s)) {
        return NULL;
    }

    ModuleNameToExec::const_iterator it = m_libraries.find(s);
    if (it == m_libraries.end()) {
        return NULL;
    } else {
        return (*it).second;
    }
}

bool Library::getInfo(const ModuleInstance *mi, uint64_t pc, std::string &file, uint64_t &line, std::string &func) {
    if (!mi) {
        return false;
    }

    vmi::ExecutableFile *exec = get(mi->Name);
    if (!exec) {
        return false;
    }

    uint64_t reladdr = pc - mi->LoadBase + mi->ImageBase;
    if (!exec->getSourceInfo(reladdr, file, line, func)) {
        return false;
    } else {
        return true;
    }
}

bool Library::print(const std::string &modName, uint64_t loadBase, uint64_t imageBase, uint64_t pc, std::string &out,
                    bool file, bool line, bool func) {
    vmi::ExecutableFile *exec = get(modName);
    if (!exec) {
        return false;
    }

    uint64_t reladdr = pc - loadBase + imageBase;
    std::string source, function;
    uint64_t ln;
    if (!exec->getSourceInfo(reladdr, source, ln, function)) {
        return false;
    }

    std::stringstream ss;

    if (file) {
        ss << source;
    }

    if (line) {
        ss << ":" << ln;
    }

    if (func) {
        ss << " - " << function;
    }

    out = ss.str();

    return true;
}

bool Library::print(const ModuleInstance *mi, uint64_t pc, std::string &out, bool file, bool line, bool func) {
    if (!mi) {
        return false;
    }

    return print(mi->Name, mi->LoadBase, mi->ImageBase, pc, out, file, line, func);
}

} // namespace s2etools
