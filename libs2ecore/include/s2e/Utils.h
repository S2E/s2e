///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
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

#ifndef S2E_UTILS_H
#define S2E_UTILS_H

#include <cassert>
#include <cstdio>
#include <deque>
#include <inttypes.h>
#include <iomanip>
#include <llvm/Support/raw_ostream.h>
#include <ostream>
#include <sstream>
#include <vector>

namespace s2e {

struct hexval {
    uint64_t value;
    int width;
    bool prefix;

    hexval(uint64_t _value, int _width = 0, bool _prefix = true) : value(_value), width(_width), prefix(_prefix) {
    }
    hexval(const void *_value, int _width = 0, bool _prefix = true)
        : value((uint64_t) _value), width(_width), prefix(_prefix) {
    }

    std::string str() const {
        std::stringstream ss;

        if (prefix) {
            ss << "0x";
        }
        ss << std::hex;
        if (width) {
            ss << std::setfill('0') << std::setw(width);
        }
        ss << value;

        return ss.str();
    }
};

inline std::ostream &operator<<(std::ostream &out, const hexval &h) {
    out << h.str();
    return out;
}

inline llvm::raw_ostream &operator<<(llvm::raw_ostream &out, const hexval &h) {
    out << h.str();
    return out;
}

struct charval {
    uint8_t value;

    charval(uint8_t value) : value(value) {
    }

    std::string str() const {
        std::stringstream ss;

        if (isalnum(value)) {
            ss << (char) value;
        } else {
            ss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (unsigned) value;
        }

        return ss.str();
    }
};

inline std::ostream &operator<<(std::ostream &out, const charval &v) {
    out << v.str();
    return out;
}

inline llvm::raw_ostream &operator<<(llvm::raw_ostream &out, const charval &v) {
    out << v.str();
    return out;
}

struct cbyte {
    uint8_t value;

    cbyte(uint8_t value) : value(value) {
    }

    std::string str() const {
        std::stringstream ss;

        if (isalnum(value)) {
            ss << "'" << (char) value << "'";
        } else {
            ss << hexval(value);
        }

        return ss.str();
    }
};

inline std::ostream &operator<<(std::ostream &out, const cbyte &v) {
    out << v.str();
    return out;
}

inline llvm::raw_ostream &operator<<(llvm::raw_ostream &out, const cbyte &v) {
    out << v.str();
    return out;
}

/*inline llvm::raw_ostream& operator<<(llvm::raw_ostream& out, const klee::ref<klee::Expr> &expr)
{
    std::stringstream ss;
    ss << expr;
    out << ss.str();
    return out;
}*/

/** A macro used to escape "," in an argument to another macro */
#define S2E_NOOP(...) __VA_ARGS__

#ifdef NDEBUG
#define DPRINTF(...)
#define TRACE(...)
#else
#define DPRINTF(...) printf(__VA_ARGS__)
#define TRACE(...)                     \
    {                                  \
        printf("%s - ", __FUNCTION__); \
        printf(__VA_ARGS__);           \
    }
#endif

/* The following is GCC-specific implementation of foreach.
   Should handle correctly all crazy C++ corner cases */

#define foreach2(_i, _b, _e) for (__typeof__(_b) _i = _b, _i##end = _e; _i != _i##end; ++_i)

/** A stream that writes both to parent streamf and cerr */
class raw_tee_ostream : public llvm::raw_ostream {
    std::deque<llvm::raw_ostream *> m_parentBufs;

    virtual void write_impl(const char *Ptr, size_t size) {
        foreach2 (it, m_parentBufs.begin(), m_parentBufs.end()) {
            (*it)->write(Ptr, size);
        }
    }

    virtual uint64_t current_pos() const {
        return 0;
    }

    virtual ~raw_tee_ostream() {
        flush();
    }

    size_t preferred_buffer_size() const {
        return 0;
    }

public:
    raw_tee_ostream(llvm::raw_ostream *master) : m_parentBufs(1, master) {
    }
    void addParentBuf(llvm::raw_ostream *buf) {
        m_parentBufs.push_front(buf);
    }
};

class raw_highlight_ostream : public llvm::raw_ostream {
    llvm::raw_ostream *m_parentBuf;

    virtual void write_impl(const char *Ptr, size_t size) {
        *m_parentBuf << "\033[31m";
        m_parentBuf->flush();
        m_parentBuf->write(Ptr, size);
        *m_parentBuf << "\033[0m";
    }

    virtual uint64_t current_pos() const {
        return 0;
    }

    virtual ~raw_highlight_ostream() {
        flush();
    }

    size_t preferred_buffer_size() const {
        return 0;
    }

public:
    raw_highlight_ostream(llvm::raw_ostream *master) : m_parentBuf(master) {
    }
};

std::string compress_file(const std::string &path);

static inline std::string ltrim(std::string s, const char *t = " \t\n\r\f\v") {
    s.erase(0, s.find_first_not_of(t));
    return s;
}

static inline std::string rtrim(std::string s, const char *t = " \t\n\r\f\v") {
    s.erase(s.find_last_not_of(t) + 1);
    return s;
}

static inline std::string trim(std::string s, const char *t = " \t\n\r\f\v") {
    return ltrim(rtrim(s, t), t);
}

bool ReadLines(const std::string &file, std::vector<std::string> &lines, bool doTrim);

uint64_t GetProcessMemoryUsage();

} // namespace s2e

#endif // S2E_UTILS_H
