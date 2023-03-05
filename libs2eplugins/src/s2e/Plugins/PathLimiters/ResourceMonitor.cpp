///
/// Copyright (C) 2015-2016, Dependable Systems Laboratory, EPFL
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

#include <qapi/qmp/qstring.h>

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/Core/Events.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "s2e/S2EExecutor.h"
#include "ResourceMonitor.h"

#include <sstream>
#include <unistd.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ResourceMonitor, "Control S2E's resource usage (memory, etc.)", "", );

void ResourceMonitor::initialize() {
    s2e()->getCorePlugin()->onStateForkDecide.connect(sigc::mem_fun(*this, &ResourceMonitor::onStateForkDecide));

    s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &ResourceMonitor::onTimer));

    m_cgroupMemLimit = 0;
    m_rss = 0;

    bool *notifiedQMP = m_notifiedQMP.acquire();
    *notifiedQMP = false;
    m_notifiedQMP.release();

    // Find out current cgroup
    std::stringstream cgroup_fname;
    cgroup_fname << "/proc/" << getpid() << "/cgroup";
    std::ifstream cgroup_file(cgroup_fname.str());
    if (!cgroup_file.is_open()) {
        getWarningsStream() << "Cannot read " << cgroup_fname.str() << " file\n";
        exit(1);
    }

    // Parse cgroup file
    std::string cgroup_name;
    for (std::string line; std::getline(cgroup_file, line);) {
        std::stringstream sline(line);
        std::string field;
        std::getline(sline, field, ':'); // Skip ID
        std::getline(sline, field, ':'); // Get name
        if (field == "memory") {
            std::getline(sline, cgroup_name, ':'); // Get cgroup name
            break;
        }
    }

    if (cgroup_name.empty() || cgroup_name == "/") {
        getWarningsStream() << "S2E is not running in a memory cgroup!\n";
        exit(1);
    }

    std::stringstream cgroup_mem_limit_fname;
    cgroup_mem_limit_fname << "/sys/fs/cgroup/memory/" << cgroup_name << "/memory.limit_in_bytes";

    // Get memory limit
    std::ifstream cgroup_mem_limit_file(cgroup_mem_limit_fname.str());
    if (!cgroup_mem_limit_file.is_open()) {
        getWarningsStream() << "Cannot read " << cgroup_mem_limit_fname.str() << " file\n";
        exit(1);
    }

    cgroup_mem_limit_file >> m_cgroupMemLimit;
    getWarningsStream() << "cgroup memory.limit_in_bytes = " << m_cgroupMemLimit << "\n";

    // Open memory stats file
    std::stringstream cgroup_mem_stat_fname;
    cgroup_mem_stat_fname << "/sys/fs/cgroup/memory/" << cgroup_name << "/memory.stat";
    m_memStatFileName = cgroup_mem_stat_fname.str();
}

void ResourceMonitor::onTimer(void) {
    if (m_timerCount < 2) {
        ++m_timerCount;
        return;
    }

    m_timerCount = 0;

    getDebugStream() << "ontimer started\n";
    updateMemoryUsage();
    if (memoryLimitExceeded()) {
        dropStates();

        bool *notifiedQMP = m_notifiedQMP.acquire();
        if (!*notifiedQMP) {
            emitQMPNofitication();
            *notifiedQMP = true;
        }
        m_notifiedQMP.release();
    }
    getDebugStream() << "ontimer ended\n";
}

void ResourceMonitor::updateMemoryUsage() {
    std::fstream memStatFile(m_memStatFileName);

    if (!memStatFile) {
        getWarningsStream() << "Cannot read " << m_memStatFileName << " file\n";
        return;
    }

    std::string line;
    while (std::getline(memStatFile, line)) {
        std::stringstream ss(line);
        std::string key;

        ss >> key;
        if (ss && key == "rss") {
            uint64_t val = 0;
            ss >> val;
            if (ss && val != 0) {
                m_rss = val;
                return;
            }
        }
    }

    getWarningsStream() << "Cannot parse " << m_memStatFileName << " file: <<END\n";
    memStatFile.seekg(0, std::ios::beg);
    while (std::getline(memStatFile, line)) {
        getWarningsStream() << line << "\n";
    }
    getWarningsStream() << "END\n";
}

void ResourceMonitor::dropStates() {
    S2EExecutor *executor = s2e()->getExecutor();
    assert(executor->getStatesCount() > 0 && "no states left to remove\n");

    // try to kill 5% of the states
    size_t nrStatesToTerminate = (size_t) (0.05 * executor->getStatesCount());

    if (nrStatesToTerminate < 1 && executor->getStatesCount() > 0) {
        nrStatesToTerminate = 1; // kill at least one state
    }

    if (nrStatesToTerminate > 0) {
        const klee::StateSet &states = s2e()->getExecutor()->getStates();
        getDebugStream() << "ResourceMonitor: will kill " << nrStatesToTerminate << " states, reason: out of memory"
                         << " #states = " << executor->getStatesCount() << "\n";
        getDebugStream() << "ResourceMonitor: limit - rss (MB) = " << ((m_cgroupMemLimit - m_rss) / 1024 / 1024)
                         << "\n";

        for (auto it = states.begin(); it != states.end() && nrStatesToTerminate > 0; it++, nrStatesToTerminate--) {
            S2EExecutionState *state = dynamic_cast<S2EExecutionState *>(*it);

            // Never kill state 0, because it is used by SeedSearcher
            if (state->getID() == 0) {
                continue;
            }

            // We might terminate the current state so the executor could throw an exception
            try {
                executor->terminateState(*state);
            } catch (s2e::CpuExitException &) {
            }
        }

    } else {
        getWarningsStream() << "ResourceMonitor: refusing to kill the only state remaining\n";
    }
}

bool ResourceMonitor::memoryLimitExceeded() {
    double diff = m_rss - 0.95 * m_cgroupMemLimit;
    if (diff > 0) {
        return true;
    } else {
        return false;
    }
}

void ResourceMonitor::onStateForkDecide(S2EExecutionState *state, const klee::ref<klee::Expr> &condition,
                                        bool &allowForking) {
    // Do not set the value to true, it is true by default.
    // Plugins can set it to false if they want to change the behavior without
    // interfering with each other.
    if (memoryLimitExceeded()) {
        allowForking = false;
    }
}

void ResourceMonitor::emitQMPNofitication() {
    Events::PluginData data;
    data.push_back(std::make_pair("type", QOBJECT(qstring_from_str("dropped_state"))));
    Events::emitQMPEvent(this, data);
}

} // namespace plugins
} // namespace s2e
