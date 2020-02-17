///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
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

#ifndef LOGGING_H
#define LOGGING_H

#include <llvm/Support/raw_ostream.h>

#define DEFAULT_CONSOLE_OUTPUT "info"
#define DEFAULT_PLUGIN_LOG_LEVEL "info"

namespace s2e {

enum LogLevel { LOG_ALL, LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_NONE };

/* The compiler complains if you don't call it */
static bool parseLogLevel(const std::string &levelString, LogLevel *out) __attribute__((unused));

static bool parseLogLevel(const std::string &levelString, LogLevel *out) {
    if (levelString == "debug") {
        *out = LOG_DEBUG;
        return true;
    } else if (levelString == "info") {
        *out = LOG_INFO;
        return true;
    } else if (levelString == "warn") {
        *out = LOG_WARN;
        return true;
    } else if (levelString == "none") {
        *out = LOG_NONE;
        return true;
    }
    return false;
}

} // namespace s2e

#endif