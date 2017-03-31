//===-- ExecutorTimers.cpp ------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Common.h"

#include "klee/CoreStats.h"
#include "klee/Executor.h"
#include "klee/PTree.h"
#include "klee/StatsTracker.h"

#include "klee/ExecutionState.h"
#include "klee/Internal/Module/InstructionInfoTable.h"
#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Module/KModule.h"
#include "klee/Internal/System/Time.h"

#include "llvm/IR/Function.h"
#include "llvm/Support/CommandLine.h"

#include <math.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef __MINGW32__
#include <windows.h>
#endif

using namespace llvm;
using namespace klee;

///

static const double kSecondsPerTick = .1;
static volatile unsigned timerTicks = 0;

// S2E: This is to avoid calling expensive time functions on the critical path
// This variable is updated evers second
volatile uint64_t g_timer_ticks = 0;

void Executor::onAlarm(int) {
    ++timerTicks;
}

#ifdef __MINGW32__
VOID CALLBACK TimerProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime) {
    // XXX: Ugly hack, but there are so many of them anyway
    ++timerTicks;
    // Executor::onAlarm(0);
}
#endif

// oooogalay
void Executor::setupTimersHandler() {
#ifdef __MINGW32__
    HANDLE hTimer;
    SetTimer(0, 0, 1000, TimerProc);
#else
    struct itimerval t;
    struct timeval tv;

    tv.tv_sec = (long) kSecondsPerTick;
    tv.tv_usec = (long) (fmod(kSecondsPerTick, 1.) * 1000000);

    t.it_interval = t.it_value = tv;

    ::setitimer(ITIMER_REAL, &t, 0);
    ::signal(SIGALRM, onAlarm);
#endif
}

void Executor::initTimers() {
    static bool first = true;

    if (first) {
        first = false;
        setupTimersHandler();
    }
}

///

Executor::Timer::Timer() {
}

Executor::Timer::~Timer() {
}

class Executor::TimerInfo {
public:
    Timer *timer;

    /// Approximate delay per timer firing.
    double rate;
    /// Wall time for next firing.
    double nextFireTime;

public:
    TimerInfo(Timer *_timer, double _rate) : timer(_timer), rate(_rate), nextFireTime(util::getWallTime() + rate) {
    }
    ~TimerInfo() {
        delete timer;
    }
};

void Executor::addTimer(Timer *timer, double rate) {
    timers.push_back(new TimerInfo(timer, rate));
}

void Executor::processTimers(ExecutionState *current) {
    static unsigned callsWithoutCheck = 0;
    unsigned ticks = timerTicks;

    ++g_timer_ticks;

    if (!ticks && ++callsWithoutCheck > 1000) {
        setupTimersHandler();
        ticks = 1;
    }

    if (ticks) {
        if (!timers.empty()) {
            double time = util::getWallTime();

            for (std::vector<TimerInfo *>::iterator it = timers.begin(), ie = timers.end(); it != ie; ++it) {
                TimerInfo *ti = *it;

                if (time >= ti->nextFireTime) {
                    ti->timer->run();
                    ti->nextFireTime = time + ti->rate;
                }
            }
        }

        timerTicks = 0;
        callsWithoutCheck = 0;
    }
}
