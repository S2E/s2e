///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
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

#include <iostream>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileSystem.h>

#include "Log.h"

using namespace llvm;

namespace {
cl::opt<std::string> LogFile("logfile", cl::desc("Where to write log output. If not specified, written to stderr."));

cl::opt<int> LogLevel("loglevel", cl::desc("Logging verbosity"), cl::init(LOG_WARNING));

cl::opt<bool> LogAll("logall", cl::desc("Logging verbosity"), cl::init(true));

cl::list<std::string> LogItems("log", llvm::cl::value_desc("log-item"), llvm::cl::Prefix,
                               llvm::cl::desc("Item to log"));

cl::list<std::string> NoLogItems("nolog", llvm::cl::value_desc("nolog-item"), llvm::cl::Prefix,
                                 llvm::cl::desc("Disable log for this item"));
} // namespace

namespace s2etools {

struct nullstream : std::ostream {
    nullstream() : std::ios(0), std::ostream(0) {
    }
};

static llvm::raw_null_ostream s_null;
static llvm::raw_fd_ostream *s_logfile;
bool Logger::s_inited = false;
Logger::TrackedKeys *Logger::s_trackedKeysFast = NULL;
Logger::KeyToString *Logger::s_trackedStrings = NULL;
Logger::StringToKey *Logger::s_trackedKeys = NULL;
unsigned Logger::s_currentKey = 0;

void Logger::Initialize() {
    if (s_inited) {
        return;
    }

    AllocateStructs();

    // First check whether we need to log everything
    if (LogAll) {
        for (auto const &trackedKey : *s_trackedKeys) {
            s_trackedKeysFast->insert(trackedKey.second);
        }
    }

    // Add all extra items
    for (auto const &LogItem : LogItems) {
        if (s_trackedKeys->find(LogItem) != s_trackedKeys->end()) {
            s_trackedKeysFast->insert((*s_trackedKeys)[LogItem]);
        }
    }

    // No check the items that we don't want to log
    for (auto const &NoLogItem : NoLogItems) {
        if (s_trackedKeys->find(NoLogItem) != s_trackedKeys->end()) {
            s_trackedKeysFast->erase((*s_trackedKeys)[NoLogItem]);
        }
    }

    if (LogFile.size() > 0) {
        std::error_code EC;
        s_logfile = new llvm::raw_fd_ostream(LogFile.c_str(), EC, llvm::sys::fs::OF_None);
    }
    s_inited = true;
}

void Logger::AllocateStructs() {
    if (s_trackedKeys) {
        return;
    }

    s_trackedKeys = new StringToKey();
    s_trackedKeysFast = new TrackedKeys();
    s_trackedStrings = new KeyToString();
}

unsigned Logger::Key(const std::string &s) {
    AllocateStructs();

    StringToKey::iterator it = s_trackedKeys->find(s);
    if (it == s_trackedKeys->end()) {
        unsigned ret;

        (*s_trackedKeys)[s] = s_currentKey;
        (*s_trackedStrings)[s_currentKey] = s;
        ret = s_currentKey++;
        return ret;
    } else {
        return (*it).second;
    }
}

LogKey::LogKey(const std::string &tag) {
    m_key = Logger::Key(tag);
    m_tag = tag;
}

int DoLog(int logLevel, const LogKey &k) {
    Logger::Initialize();
    if (!k.isTracked()) {
        return 0;
    }

    if (logLevel < LogLevel) {
        return 0;
    }
    return 1;
}

llvm::raw_ostream &Log(int logLevel, const LogKey &k) {
    Logger::Initialize();
    if (!k.isTracked()) {
        return s_null;
    }

    if (logLevel < LogLevel) {
        return s_null;
    }

    if (LogFile.size() == 0) {
        return llvm::outs();
    }

    return *s_logfile;
}
} // namespace s2etools
