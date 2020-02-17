///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014, Cyberhaven
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

#ifndef S2E_PLUGINS_HOSTFILES_H
#define S2E_PLUGINS_HOSTFILES_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>
#include <set>
#include <string>

namespace s2e {
namespace plugins {

enum HOSTFILESACTION { READ, WRITE };

struct HostFD {
    int fd;
    HOSTFILESACTION type;
};

class HostFiles : public Plugin {
    S2E_PLUGIN
public:
    HostFiles(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    std::vector<std::string> m_baseDirectories;
    bool m_allowWrite;

    void open(S2EExecutionState *state);
    void close(S2EExecutionState *state);
    void read(S2EExecutionState *state);
    void create(S2EExecutionState *state);
    void write(S2EExecutionState *state);

    void onCustomInstruction(S2EExecutionState *state, uint64_t opcode);
    void onStateFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                     const std::vector<klee::ref<klee::Expr>> &newConditions);
};

////////////////////////////////////////////////////////////////////////////////

class HostFilesState : public PluginState {
private:
    std::vector<HostFD> m_openFiles;

    int nb_open; // Number of files that have been open and not closed

public:
    HostFilesState();
    HostFilesState(S2EExecutionState *s, Plugin *p);
    virtual ~HostFilesState();
    virtual PluginState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    friend class HostFiles;
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_HOSTFILES_H
