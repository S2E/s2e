///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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