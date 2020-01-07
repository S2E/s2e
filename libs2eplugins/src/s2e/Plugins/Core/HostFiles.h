///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
