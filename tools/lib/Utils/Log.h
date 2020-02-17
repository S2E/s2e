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

#ifndef S2ETOOLS_LOG_H
#define S2ETOOLS_LOG_H

#include <llvm/ADT/DenseSet.h>
#include <llvm/Support/raw_ostream.h>
#include <map>
#include <string>

#define LOG_DEBUG 0
#define LOG_INFO 1
#define LOG_WARNING 3
#define LOG_ERROR 4

namespace s2etools {

class LogKey;

class Logger {
    friend class LogKey;

public:
    typedef llvm::DenseSet<unsigned> TrackedKeys;
    typedef std::map<unsigned, std::string> KeyToString;
    typedef std::map<std::string, unsigned> StringToKey;

private:
    Logger();
    static bool s_inited;
    static unsigned s_currentKey;

    // These have to be pointers because of static intializing issues
    static TrackedKeys *s_trackedKeysFast;
    static KeyToString *s_trackedStrings;
    static StringToKey *s_trackedKeys;

    static void AllocateStructs();

public:
    static void Initialize();
    static unsigned Key(const std::string &s);
};

class LogKey {
private:
    unsigned m_key;
    std::string m_tag;

public:
    LogKey(const std::string &tag);
    inline bool isTracked() const {
        return Logger::s_trackedKeysFast->count(m_key);
    }
    inline const std::string &getTag() const {
        return m_tag;
    }
};

/** Get the logging stream */
llvm::raw_ostream &Log(int logLevel, const LogKey &k);

int DoLog(int level, const LogKey &k);

#define __LOG_SUFFIX(level) \
    s2etools::Log(level, TAG) << '[' << level << "] " << TAG.getTag() << ":" << __FUNCTION__ << " - "

#define LOGDEBUG(a)            \
    if (DoLog(LOG_DEBUG, TAG)) \
    __LOG_SUFFIX(LOG_DEBUG) << a
#define LOGWARNING(a)            \
    if (DoLog(LOG_WARNING, TAG)) \
    __LOG_SUFFIX(LOG_WARNING) << a
#define LOGINFO(a)            \
    if (DoLog(LOG_INFO, TAG)) \
    __LOG_SUFFIX(LOG_INFO) << a
#define LOGERROR(a)            \
    if (DoLog(LOG_ERROR, TAG)) \
    __LOG_SUFFIX(LOG_ERROR) << a
} // namespace s2etools

#endif
