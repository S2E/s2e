///
/// Copyright (C) 2016, Cyberhaven
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

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <klee/Internal/ADT/ImmutableSet.h>

#include <s2e/cpu.h>

extern "C" {
#include "qdict.h"
#include "qint.h"
#include "qjson.h"
#include "qlist.h"
}

#include "CallSiteMonitor.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(CallSiteMonitor, "CallSiteMonitor S2E plugin", "", "OSMonitor", "ProcessExecutionDetector",
                  "ModuleExecutionDetector");

void CallSiteMonitor::initialize() {
    m_procDetector = s2e()->getPlugin<ProcessExecutionDetector>();
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();
    m_monitor = dynamic_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));

    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(sigc::mem_fun(*this, &CallSiteMonitor::onTranslateBlockEnd));

    m_dumpPeriod = s2e()->getConfig()->getInt(getConfigKey() + ".dumpInfoInterval", 0);
    if (m_dumpPeriod > 0) {
        s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &CallSiteMonitor::onTimer));
    }

    m_lastDumpedTime = 0;
}

void CallSiteMonitor::onTimer() {
    ++m_lastDumpedTime;
    if (m_lastDumpedTime <= m_dumpPeriod) {
        return;
    }

    generateJsonFile();
    m_lastDumpedTime = 0;
}

void CallSiteMonitor::onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                          uint64_t pc, bool isStatic, uint64_t staticTarget) {
    if ((tb->flags & HF_CPL_MASK) != 3) {
        return;
    }

    if (!m_procDetector->isTracked(state)) {
        return;
    }

    CallSite cs;

    bool isIndirect =
        tb->se_tb_type == TB_CALL_IND || tb->se_tb_type == TB_JMP_IND || tb->se_tb_type == TB_COND_JMP_IND;

    // TODO: do we need to convert absolute addresses to per-module?
    // TODO: mark calls that get into JIT regions?
    if (tb->se_tb_type == TB_CALL) {
        cs.source = pc;
        cs.target = staticTarget;
        cs.type = CALL;

        uint64_t pid = m_monitor->getPid(state);
        std::string processName = "<unknown_process>";
        m_monitor->getProcessName(state, pid, processName);

        m_callSites[processName].insert(cs);
    } else if (isIndirect) {
        signal->connect(sigc::bind(sigc::mem_fun(*this, &CallSiteMonitor::onInstruction), (unsigned) tb->se_tb_type));
    }
}

void CallSiteMonitor::onInstruction(S2EExecutionState *state, uint64_t source_pc, unsigned source_type) {
    if (!m_procDetector->isTracked(state)) {
        return;
    }

    CallSite cs;
    cs.source = source_pc;

    // The pc is always concrete here
    cs.target = state->regs()->getPc();

    if (source_type == TB_CALL_IND) {
        cs.type = INDIRECT_CALL;
    } else {
        cs.type = INDIRECT_JUMP;
    }

    // TODO: make this faster
    if (!m_detector->getModule(state, cs.source)) {
        cs.type = static_cast<CallSiteType>(static_cast<int>(cs.type) | JIT_SOURCE);
    }

    if (!m_detector->getModule(state, cs.target)) {
        cs.type = static_cast<CallSiteType>(static_cast<int>(cs.type) | JIT_TARGET);
    }

    uint64_t pid = m_monitor->getPid(state);

    std::string processName = "<unknown_process>";
    m_monitor->getProcessName(state, pid, processName);

    // TODO: might need per-state tracking?
    m_callSites[processName].insert(cs);
}

std::string CallSiteMonitor::generateJsonFile() {
    std::string path;

    std::stringstream fileName;
    fileName << "callsites.json";
    path = s2e()->getOutputFilename(fileName.str());

    generateJsonFile(path);

    return path;
}

void CallSiteMonitor::generateJsonFile(const std::string &path) {
    std::stringstream result;
    generateJson(result);

    std::ofstream o(path.c_str());
    o << result.str();
    o.close();
}

void CallSiteMonitor::generateJson(std::stringstream &callSiteInfo) {
    QDict *pt = qdict_new();

    for (auto it : m_callSites) {
        std::string processName = it.first;
        const CallSites &callSites = it.second;

        QList *qcall_sites = qlist_new();
        for (auto cit : callSites) {
            const CallSite &cs = cit;
            QList *info = qlist_new();
            qlist_append_obj(info, QOBJECT(qint_from_int(cs.source)));
            qlist_append_obj(info, QOBJECT(qint_from_int(cs.target)));
            qlist_append_obj(info, QOBJECT(qint_from_int(cs.type)));
            qlist_append_obj(qcall_sites, QOBJECT(info));
        }

        qdict_put_obj(pt, processName.c_str(), QOBJECT(qcall_sites));
    }

    QString *json = qobject_to_json(QOBJECT(pt));

    callSiteInfo << qstring_get_str(json) << "\n";

    QDECREF(json);
    QDECREF(pt);
}

} // namespace plugins
} // namespace s2e
