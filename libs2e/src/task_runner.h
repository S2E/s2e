///
/// Copyright (C) 2026, Vitaly Chipounov
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

#ifndef S2E_TASK_RUNNER_H
#define S2E_TASK_RUNNER_H

#include <pthread.h>

#include <deque>
#include <functional>
#include <mutex>

class TaskRunner {
private:
    pthread_t m_thread;
    std::mutex m_mutex;
    std::deque<std::function<void()>> m_tasks;

public:
    TaskRunner() : m_thread(pthread_self()) {};
    ~TaskRunner() = default;

    bool run_on_thread() {
        if (!pthread_equal(pthread_self(), m_thread)) {
            return false;
        }

        std::deque<std::function<void()>> tasks;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            tasks.swap(m_tasks);
        }

        for (auto &task : tasks) {
            task();
        }

        return true;
    }

    bool run_on_thread(std::function<void()> task) {
        if (!pthread_equal(pthread_self(), m_thread)) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_tasks.push_back(std::move(task));
            return false;
        }

        task();
        return true;
    }
};

#endif
