///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
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

#include <s2e/cpu.h>
#include <s2e/opcodes.h>

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include "HostFiles.h"

#include <errno.h>
#include <iostream>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <llvm/Config/config.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(HostFiles, "Access to host files", "", );

void HostFiles::initialize() {
    m_allowWrite = s2e()->getConfig()->getBool(getConfigKey() + ".allowWrite", false, nullptr);

    ConfigFile::string_list dirs = s2e()->getConfig()->getStringList(getConfigKey() + ".baseDirs");

    foreach2 (it, dirs.begin(), dirs.end()) { m_baseDirectories.push_back(*it); }

    foreach2 (it, m_baseDirectories.begin(), m_baseDirectories.end()) {
        if (!llvm::sys::fs::exists((*it))) {
            getWarningsStream() << "Path " << (*it) << " does not exist\n";
            exit(-1);
        }
    }

    if (m_baseDirectories.empty()) {
        m_baseDirectories.push_back(s2e()->getOutputDirectory());
    }

    s2e()->getCorePlugin()->onCustomInstruction.connect(sigc::mem_fun(*this, &HostFiles::onCustomInstruction));

    s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &HostFiles::onStateFork));
}

void HostFiles::open(S2EExecutionState *state) {
    // Get the plugin state for the current path
    DECLARE_PLUGINSTATE(HostFilesState, state);

    target_ulong fnamePtr = 0, flags = 0;
    target_ulong guestFd = (target_ulong) -1;
    bool ok = true;
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EBX]), &fnamePtr, sizeof(target_ulong), false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_ECX]), &flags, sizeof(target_ulong), false);

    state->regs()->write(CPU_OFFSET(regs[R_EAX]), &guestFd, sizeof(target_ulong));

    if (!ok) {
        getWarningsStream(state) << "ERROR: symbolic argument was passed to s2e_op HostFiles " << '\n';
        return;
    }

    std::string fname;
    if (!state->mem()->readString(fnamePtr, fname) || fname.size() == 0) {
        getWarningsStream(state) << "Error reading file name string from the guest" << '\n';
        return;
    }

    getDebugStream(state) << "opening " << fname << "\n";

    /* Check that there aren't any ../ in the path */
    if (fname.find("..") != std::string::npos) {
        getWarningsStream(state) << "HostFiles: file name must not contain .. sequences (" << fname << ")\n;";
        return;
    }

    llvm::SmallString<128> path;

    /* Find the path prefix for the given relative file */
    foreach2 (it, m_baseDirectories.begin(), m_baseDirectories.end()) {
        path = *it;
        llvm::sys::path::append(path, fname);
        if (llvm::sys::fs::exists(path)) {
            break;
        }
    }

    int oflags = O_RDONLY;
#ifdef CONFIG_WIN32
    oflags |= O_BINARY;
#endif

    int fd = ::open(path.c_str(), oflags);
    if (fd != -1) {
        HostFD hf = {fd, READ};
        plgState->m_openFiles.push_back(hf);
        ++(plgState->nb_open);
        guestFd = plgState->m_openFiles.size() - 1;
        state->regs()->write(CPU_OFFSET(regs[R_EAX]), &guestFd, sizeof(target_ulong));
    } else {
        getWarningsStream(state) << "could not open " << path << "(errno " << errno << ")" << '\n';
    }
}

void HostFiles::read(S2EExecutionState *state) {
    // Get the plugin state for the current path
    DECLARE_PLUGINSTATE(HostFilesState, state);

    target_ulong guestFd, bufAddr, count;
    target_ulong ret = (target_ulong) -1;
    ssize_t read_ret = -1;

    bool ok = true;
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EBX]), &guestFd, sizeof(target_ulong), false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_ECX]), &bufAddr, sizeof(target_ulong), false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EDX]), &count, sizeof(target_ulong), false);

    state->regs()->write(CPU_OFFSET(regs[R_EAX]), &ret, sizeof(target_ulong));

    if (!ok) {
        getWarningsStream(state) << "ERROR: symbolic argument was passed to s2e_op HostFiles" << '\n';
        return;
    }

    if (count > 1024 * 64) {
        getWarningsStream(state) << "ERROR: count passed to HostFiles is too big" << '\n';
        return;
    }

    if (guestFd > plgState->m_openFiles.size() || plgState->m_openFiles[guestFd].fd == -1) {
        getWarningsStream(state) << "ERROR: invalid file handle passed to HostFiles\n";
        return;
    }

    if (plgState->m_openFiles[guestFd].type != READ) {
        getWarningsStream(state) << "ERROR: file passed to HostFiles cannot be read (bad permissions)\n";
    }

    HostFD hf = plgState->m_openFiles[guestFd];
    char buf[count];

    read_ret = ::read(hf.fd, buf, count);
    if (-1 == read_ret) {
        return;
    }
    ret = read_ret;

    ok = state->mem()->write(bufAddr, buf, ret);
    if (!ok) {
        getWarningsStream(state) << "ERROR: HostFiles can not write to guest buffer\n";
        return;
    }

    state->regs()->write(CPU_OFFSET(regs[R_EAX]), &ret, sizeof(target_ulong));
}

void HostFiles::close(S2EExecutionState *state) {
    // Get the plugin state for the current path
    DECLARE_PLUGINSTATE(HostFilesState, state);

    target_ulong guestFd;
    target_ulong ret = (target_ulong) -1;

    bool ok = true;
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EBX]), &guestFd, sizeof(target_ulong), false);

    state->regs()->write(CPU_OFFSET(regs[R_EAX]), &ret, sizeof(target_ulong));

    if (!ok) {
        getWarningsStream(state) << "ERROR: symbolic argument was passed to HostFiles\n";
        return;
    }

    if (guestFd < plgState->m_openFiles.size() && plgState->m_openFiles[guestFd].fd != -1) {

        ret = ::close(plgState->m_openFiles[guestFd].fd);
        plgState->m_openFiles[guestFd].fd = -1;
        (--plgState->nb_open);

        state->regs()->write(CPU_OFFSET(regs[R_EAX]), &ret, sizeof(target_ulong));

    } else {
        getWarningsStream(state) << "ERROR: invalid file handle passed to HostFiles\n";
    }
}

/* Create a new file write only */
void HostFiles::create(S2EExecutionState *state) {
    // Get the plugin state for the current path
    DECLARE_PLUGINSTATE(HostFilesState, state);

    target_ulong fnamePtr = 0, flags = 0;
    target_ulong guestFd = (target_ulong) -1;
    bool ok = true;
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EBX]), &fnamePtr, sizeof(target_ulong), false);

    ok &= state->regs()->read(CPU_OFFSET(regs[R_ECX]), &flags, sizeof(target_ulong), false);

    state->regs()->write(CPU_OFFSET(regs[R_EAX]), &guestFd, sizeof(target_ulong));

    if (!m_allowWrite) {
        getWarningsStream(state) << "HostFiles : writes are disabled\n";
        return;
    }

    if (!ok) {
        getWarningsStream(state) << "ERROR: symbolic argument was passed to s2e_op HostFiles " << '\n';
        return;
    }

    std::string fname;
    if (!state->mem()->readString(fnamePtr, fname) || fname.size() == 0) {
        getWarningsStream(state) << "Error reading file name string from the guest" << '\n';
        return;
    }

    /* Check that there aren't any ../ in the path */
    if (fname.find("..") != std::string::npos) {
        getWarningsStream(state) << "HostFiles: file name must not contain .. sequences (" << fname << ")\n;";
        return;
    }

    if (fname.find("/") != std::string::npos) {
        getWarningsStream(state) << "HostFiles: file name must not contain '/' characters (" << fname << ")\n;";
        return;
    }

    llvm::SmallString<128> path(s2e()->getOutputDirectoryBase());

    /* Create a subfolder for all dumped files */
    llvm::sys::path::append(path, "outfiles");

    /* Each state has its personal subfolder */
    llvm::sys::path::append(path, llvm::Twine(state->getID()));

    if (!llvm::sys::fs::exists(path)) {
        /* Create folder if it doesn't exist */
        std::error_code err = llvm::sys::fs::create_directories(path.str());
        if (err) {
            getWarningsStream(state) << "HostFiles: couldn't create directory (" << path.str()
                                     << "), err : " << err.value() << "\n;";
        }
    }

    if (!llvm::sys::fs::is_directory(path)) {
        getWarningsStream(state) << "HostFiles: couldn't create directory, file exists (" << path.str() << ")\n;";
        return;
    }

    llvm::sys::path::append(path, fname);

    if (llvm::sys::fs::exists(path.str())) {
        getWarningsStream(state) << "HostFiles: file exists, cannot create (" << fname << ")\n;";
        return;
    }

    int fd;
#ifdef CONFIG_WIN32
    fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, S_IRWXU);
#else
    fd = ::creat(path.c_str(), S_IRWXU);
#endif

    if (fd != -1) {
        HostFD hf = {fd, WRITE};
        plgState->m_openFiles.push_back(hf);
        guestFd = plgState->m_openFiles.size() - 1;
        (++plgState->nb_open);

        state->regs()->write(CPU_OFFSET(regs[R_EAX]), &guestFd, sizeof(target_ulong));
    } else {
        getWarningsStream(state) << "HostFiles could not open " << path << "(errno " << errno << ")" << '\n';
    }
}

void HostFiles::write(S2EExecutionState *state) {
    // Get the plugin state for the current path
    DECLARE_PLUGINSTATE(HostFilesState, state);

    target_ulong guestFd, bufAddr, count;
    target_ulong ret = (target_ulong) -1;
    ssize_t write_ret = -1;

    bool ok = true;
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EBX]), &guestFd, sizeof(target_ulong), false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_ECX]), &bufAddr, sizeof(target_ulong), false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EDX]), &count, sizeof(target_ulong), false);

    state->regs()->write(CPU_OFFSET(regs[R_EAX]), &ret, sizeof(target_ulong));

    if (!ok) {
        getWarningsStream(state) << "ERROR: symbolic argument was passed to s2e_op HostFiles" << '\n';
        return;
    }

    if (count > 1024 * 64) {
        getWarningsStream(state) << "ERROR: count passed to HostFiles is too big" << '\n';
        return;
    }

    if (guestFd > plgState->m_openFiles.size() || plgState->m_openFiles[guestFd].fd == -1) {
        getWarningsStream(state) << "ERROR: invalid file handle passed to HostFiles\n";
        return;
    }

    if (plgState->m_openFiles[guestFd].type != WRITE) {
        getWarningsStream(state) << "ERROR: file passed to HostFiles cannot be written to"
                                 << "(bad permissions)\n";
    }

    HostFD hf = plgState->m_openFiles[guestFd];
    char buf[count];

    ok = state->mem()->read(bufAddr, buf, count);
    if (!ok) {
        getWarningsStream(state) << "ERROR: HostFiles can not read guest buffer\n";
        return;
    }

    write_ret = ::write(hf.fd, buf, count);
    if (-1 == write_ret)
        return;
    ret = write_ret;

    state->regs()->write(CPU_OFFSET(regs[R_EAX]), &ret, sizeof(target_ulong));
}

void HostFiles::onCustomInstruction(S2EExecutionState *state, uint64_t opcode) {
    // XXX: find a better way of allocating custom opcodes
    if (!OPCODE_CHECK(opcode, HOST_FILES_OPCODE)) {
        return;
    }

    opcode >>= 16;
    uint8_t op = opcode & 0xFF;
    opcode >>= 8;

    switch (op) {
        case HOST_FILES_OPEN_OPCODE: {
            open(state);
            break;
        }

        case HOST_FILES_CLOSE_OPCODE: {
            close(state);
            break;
        }

        case HOST_FILES_READ_OPCODE: {
            read(state);
            break;
        }

        case HOST_FILES_CREATE_OPCODE: {
            create(state);
            break;
        }

        case HOST_FILES_WRITE_OPCODE: {
            write(state);
            break;
        }

        default:
            getWarningsStream(state) << "Invalid HostFiles opcode " << hexval(op) << '\n';
            break;
    }
}

void HostFiles::onStateFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                            const std::vector<klee::ref<klee::Expr>> &newConditions) {
    // Get the plugin state for the current path
    DECLARE_PLUGINSTATE(HostFilesState, state);

    if (plgState->nb_open > 0) {
        getWarningsStream(state) << "HostFiles : Forking new state with "
                                 << "open files, expect errors!\n";
    }
}

///////////////////////////////////////////////////////////////////////////////

HostFilesState::HostFilesState() : m_openFiles() {
    nb_open = 0;
}

HostFilesState::HostFilesState(S2EExecutionState *s, Plugin *p) : m_openFiles() {
    nb_open = 0;
}

HostFilesState::~HostFilesState() {
}

PluginState *HostFilesState::clone() const {
    return new HostFilesState();
}

PluginState *HostFilesState::factory(Plugin *p, S2EExecutionState *s) {
    return new HostFilesState(s, p);
}

} // namespace plugins
} // namespace s2e
