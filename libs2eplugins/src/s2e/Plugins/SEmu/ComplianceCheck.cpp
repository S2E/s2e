//
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "ComplianceCheck.h"
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/SymbolicHardwareHook.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>
#include <sys/shm.h>
#include <time.h>
#include <algorithm>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ComplianceCheck, "Complaince Check Model", "ComplianceCheckModel");

void ComplianceCheck::initialize() {
    onNLPPeripheralModelConnection = s2e()->getPlugin<NLPPeripheralModel>();
    onNLPPeripheralModelConnection->onHardwareWrite.connect(
        sigc::mem_fun(*this, &ComplianceCheck::onHardwareWrite));
    onNLPPeripheralModelConnection->onFirmwareWrite.connect(
        sigc::mem_fun(*this, &ComplianceCheck::onPeripheralWrite));
    onNLPPeripheralModelConnection->onFirmwareRead.connect(
        sigc::mem_fun(*this, &ComplianceCheck::onPeripheralRead));
    onNLPPeripheralModelConnection->onFirmwareCheck.connect(
        sigc::mem_fun(*this, &ComplianceCheck::onFork));

    CCfileName = s2e()->getConfig()->getString(getConfigKey() + ".CCfileName", "all.txt");
    getDebugStream() << "CC peripheral model file name is " << CCfileName << "\n";

    s2e()->getCorePlugin()->onEngineShutdown.connect(sigc::mem_fun(*this, &ComplianceCheck::onComplianceCheck));
}

bool ComplianceCheck::readCCModelfromFile(S2EExecutionState *state, std::string &fileName) {
    std::ifstream fNLP;
    std::string line;
    fNLP.open(fileName, std::ios::in);
    if (!fNLP) {
        getWarningsStream() << "Could not open cache CC file: " << fileName << "\n";
        exit(-1);
        return false;
    }

    std::string peripheralcache;
    while (getline(fNLP, peripheralcache)) {
        if (peripheralcache == "==")
            break;
        if (!getSequences(peripheralcache))
            return false;
    }
    read_data = true;
    return true;
}

bool ComplianceCheck::getSequences(std::string &peripheralcache) {
    getDebugStream() << peripheralcache << "\n";
    std::vector<std::string> actions;
    SplitString(peripheralcache, actions, "->");
    std::vector<FieldList> ans;
    for (auto &action : actions) {
        std::vector<std::string> seqs;
        SplitString(action, seqs, "&");
        FieldList tmp;
        for (auto &seq : seqs) {
            Field field;
            ReadField(seq, field);
            tmp.push_back(field);
        }
        ans.push_back(tmp);
    }
    sequences.push_back(ans);
    return true;
}

void ComplianceCheck::ReadField(std::string &expressions, Field &field) {
    getDebugStream() << expressions << "\n";
    std::vector<std::string> v;
    SplitString(expressions, v, ",");
    field.type = v[0];
    field.phaddr = std::stoull(v[1].c_str(), NULL, 16);
    field.bits = getBits(v[2]);
    if (v.size() == 5 && v[4] != "*") {
        field.value = std::stoull(v[4].c_str(), NULL, 2);
    }
}

std::vector<long> ComplianceCheck::getBits(std::string &bits) {
    std::vector<long> res;
    if (bits == "*")
        return {-1};
    else {
        SplitStringToInt(bits, res, "/", 10);
        return res;
    }
}

void ComplianceCheck::SplitStringToInt(const std::string &s, std::vector<long> &v, const std::string &c, int dtype) {
    std::string::size_type pos1, pos2;
    pos2 = s.find(c);
    pos1 = 0;
    while (std::string::npos != pos2) {
        v.push_back(std::strtol(s.substr(pos1, pos2 - pos1).c_str(), NULL, dtype));
        pos1 = pos2 + c.size();
        pos2 = s.find(c, pos1);
    }
    if (pos1 != s.length()) {
        v.push_back(std::strtol(s.substr(pos1).c_str(), NULL, dtype));
    }
}

void ComplianceCheck::SplitString(const std::string &s, std::vector<std::string> &v, const std::string &c) {
    std::string::size_type pos1, pos2;
    pos2 = s.find(c);
    pos1 = 0;
    while (std::string::npos != pos2) {
        v.push_back(s.substr(pos1, pos2 - pos1));
        pos1 = pos2 + c.size();
        pos2 = s.find(c, pos1);
    }
    if (pos1 != s.length())
        v.push_back(s.substr(pos1));
}

void ComplianceCheck::onHardwareWrite(S2EExecutionState *state, uint32_t phaddr, uint32_t cur_val, int32_t irq) {
    if (!read_data)
        readCCModelfromFile(state, CCfileName);
    cur_time++;
    recording_write[phaddr].push_back(Access("HW", cur_time, irq, phaddr, cur_val, state->regs()->getPc()));
}

void ComplianceCheck::onPeripheralRead(S2EExecutionState *state, uint32_t phaddr, uint32_t cur_val, int32_t irq) {
    getDebugStream() << "ComplianceCheck READ"
                     << "\n";
    if (!read_data)
        readCCModelfromFile(state, CCfileName);
    cur_time++;
    recording_write[phaddr].push_back(Access("FW", cur_time, irq, phaddr, cur_val, state->regs()->getPc()));
}

void ComplianceCheck::onPeripheralWrite(S2EExecutionState *state, uint32_t phaddr, uint32_t cur_val, int32_t irq) {
    getDebugStream() << "ComplianceCheck WRITE"
                     << "\n";
    if (!read_data)
        readCCModelfromFile(state, CCfileName);
    cur_time++;
    recording_write[phaddr].push_back(Access("FW", cur_time, irq, phaddr, cur_val, state->regs()->getPc()));
}

void ComplianceCheck::onFork(S2EExecutionState *state, uint32_t phaddr, uint32_t cur_val, int32_t irq, bool check) {
    getDebugStream() << "ComplianceCheck WRITE"
                     << "\n";
    if (!read_data)
        readCCModelfromFile(state, CCfileName);
    if (!check)
        cur_time++;
    recording_write[phaddr].push_back(Access("FW", cur_time, irq, phaddr, cur_val, state->regs()->getPc()));
}

bool ComplianceCheck::checkField(Field &field, uint32_t cur_value) {
    if (field.bits[0] == -1)
        return true;

    uint32_t res = 0;
    for (int i = 0; i < field.bits.size(); ++i) {
        int tmp = field.bits[i];
        res = (res << 1) + (cur_value >> tmp & 1);
    }
    return res == field.value;
}

void ComplianceCheck::getExsitence(std::vector<Access> &accesses, Field &rule, AccessPair &new_existence) {
    for (auto &access : accesses) {
        if (!checkField(rule, access.cur_value))
            continue;
        new_existence[access.irq].push_back(access.time);
    }
}

void ComplianceCheck::checkAtomic(std::vector<AccessPair> &existence_seq, Race &races) {
    for (auto idx = existence_seq.size() - 1; idx > 0; --idx) {
        for (auto &rule : existence_seq[idx]) {
            for (auto &t : rule.second) {
                auto prev_time = t - 1;
                std::vector<uint32_t> &tmp = existence_seq[idx - 1][rule.first];
                if (find(tmp.begin(), tmp.end(), prev_time) == tmp.end()) {
                    races.push_back({prev_time, t});
                }
            }
        }
    }
}

void ComplianceCheck::type1Check(Race &races) {
    for (auto &seq : sequences) {
        std::vector<AccessPair> existence_seq;
        for (auto &rule : seq) {
            std::vector<AccessPair> rules_existence;
            for (Field &f : rule) {
                AccessPair access;
                if (f.type == "CC") {
                    if (recording_check.find(f.phaddr) == recording_check.end()) continue;
                    getExsitence(recording_check[f.phaddr], f, access);
                } else if (f.type == "CW") {
                    if (recording_write.find(f.phaddr) == recording_write.end()) continue;
                    getExsitence(recording_write[f.phaddr], f, access);
                } else if (f.type == "CR") {
                    if (recording_read.find(f.phaddr) == recording_read.end()) continue;
                    getExsitence(recording_read[f.phaddr], f, access);
                }
                if (access.size() == 0) break;
                rules_existence.push_back(access);
            }
            if (rules_existence.size() == 0) {
                existence_seq.clear();
                break;
            } else if (rules_existence.size() == 1) {
                existence_seq.push_back(rules_existence[0]);
            } else {
                existence_seq.clear();
                getWarningsStream() << "cannot handle two rules now!"
                                    << "\n";
                break;
            }
        }
        if (existence_seq.size() != 0)
            checkAtomic(existence_seq, races);
    }
}

void ComplianceCheck::onComplianceCheck() {
    Race races;
    type1Check(races);
    if (races.size() == 0) return;

    getInfoStream() << "write Compliance Check files\n";
    std::string NLPstafileName = s2e()->getOutputDirectory() + "/" + "ComplianceCheck.dat";
    std::ofstream fPHNLP;
    fPHNLP.open(NLPstafileName, std::ios::out | std::ios::trunc);

    std::map<int32_t, std::vector<access>> all_recordings;
    for (auto &record : recording_read) {
        for (auto &access : record.second) {
            all_recordings[access.time].push_back(access);
        }
    }
    for (auto &record : recording_write) {
        for (auto &access : record.second) {
            all_recordings[access.time].push_back(access);
        }
    }
    for (auto &record : recording_check) {
        for (auto &access : record.second) {
            all_recordings[access.time].push_back(access);
        }
    }
    fPHNLP << "-------Compliance Check Results-------\n";
    for (auto &race : races) {
        for (auto &time : race) {
            for (auto &access : all_recordings[time])
                fPHNLP << "time: " << access.time << " type: " << access.type << " irq: " << access.irq << " phaddr: " << access.phaddr << " pc: " << access.pc << "\n";
        }
        fPHNLP << "==================\n";
    }

    fPHNLP.close();
}

}
} // namespace s2e::plugins
