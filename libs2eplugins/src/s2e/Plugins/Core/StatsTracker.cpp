///
/// Copyright (C) 2022, Vitaly Chipounov
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

#include <cassert>

#include <klee/Stats/StatisticManager.h>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "StatsTracker.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(StatsTracker, "Write statistics into the stats.csv CSV file", "", );

void StatsTracker::initialize() {
    // The logic is similar to ExecutionTracer.
    createNewStatsFile(false);

    s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &StatsTracker::onTimer),
                                            fsigc::signal_base::HIGHEST_PRIORITY);

    s2e()->getCorePlugin()->onProcessFork.connect(sigc::mem_fun(*this, &StatsTracker::onProcessFork),
                                                  fsigc::signal_base::HIGHEST_PRIORITY);

    s2e()->getCorePlugin()->onEngineShutdown.connect(sigc::mem_fun(*this, &StatsTracker::onEngineShutdown));
}

StatsTracker::~StatsTracker() {
    onEngineShutdown();
}

void StatsTracker::createNewStatsFile(bool append) {
    if (append) {
        assert(mFileName.size() > 0);
        mFile = fopen(mFileName.c_str(), "a");
    } else {
        mFileName = s2e()->getOutputFilename("stats.csv");
        mFile = fopen(mFileName.c_str(), "wb");

        if (mFile != nullptr) {
            auto mgr = klee::stats::getStatisticManager();
            auto hdr = mgr->getCSVHeader();
            if (fwrite(hdr.c_str(), hdr.size(), 1, mFile) != 1) {
                getWarningsStream() << "Could not write header to " << mFileName << "\n";
                exit(-1);
            }
        }
    }

    if (!mFile) {
        getWarningsStream() << "Could not create ExecutionTracer.dat" << '\n';
        exit(-1);
    }
}

void StatsTracker::onTimer() {
    if (mFile) {
        klee::stats::memoryUsage->setValue(s2e::GetProcessMemoryUsage());

        auto mgr = klee::stats::getStatisticManager();
        auto hdr = mgr->getCSVLine();
        if (fwrite(hdr.c_str(), hdr.size(), 1, mFile) != 1) {
            getWarningsStream() << "Could not write header to " << mFileName << "\n";
            exit(-1);
        }
        fflush(mFile);
    }
}

void StatsTracker::onProcessFork(bool preFork, bool isChild, unsigned parentProcId) {
    if (preFork) {
        fclose(mFile);
        mFile = nullptr;
    } else {
        if (isChild) {
            createNewStatsFile(false);
        } else {
            createNewStatsFile(true);
        }
    }
}

void StatsTracker::onEngineShutdown() {
    if (mFile) {
        // Print out latest stats.
        onTimer();
        fclose(mFile);
        mFile = nullptr;
    }
}

} // namespace plugins
} // namespace s2e