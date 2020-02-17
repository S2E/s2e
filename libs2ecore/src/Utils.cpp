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

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>

#if defined(CONFIG_WIN32)
static void print_stacktrace(const char *reason) {
    std::ostream &os = g_s2e->getDebugStream();
    os << "Stack trace printing unsupported on Windows" << '\n';
}
#else
#include <cxxabi.h>
#include <execinfo.h>
#include <llvm/Support/raw_ostream.h>
#include <s2e/S2E.h>
#include <s2e/s2e_libcpu.h>
#include <stdio.h>
#include <stdlib.h>

#include <s2e/Utils.h>

// stacktrace.h (c) 2008, Timo Bingmann from http://idlebox.net/
// published under the WTFPL v2.0

/** Print a demangled stack backtrace of the caller function to FILE* out. */
void print_stacktrace(void (*print_func)(const char *fmt, ...), const char *reason) {
    // storage array for stack trace address data
    static const unsigned MAX_FRAMES = 63;
    void *addrlist[MAX_FRAMES + 1];

    print_func("\nPrinting stack trace (%s)\n", reason);

    // retrieve current stack addresses
    int addrlen = backtrace(addrlist, sizeof(addrlist) / sizeof(void *));

    if (addrlen == 0) {
        print_func("  <empty, possibly corrupt>\n");
        return;
    }

    // resolve addresses into strings containing "filename(function+address)",
    // this array must be free()-ed
    char **symbollist = backtrace_symbols(addrlist, addrlen);

    // allocate string which will be filled with the demangled function name
    size_t funcnamesize = 256;
    char *funcname = (char *) malloc(funcnamesize);

    // iterate over the returned symbol lines. skip the first, it is the
    // address of this function.
    for (int i = 1; i < addrlen; i++) {
        // find parentheses containing function name and offset
        // ./module(function+0x15c) [0x8048a6d]
        char *begin_name = strchr(symbollist[i], '(');
        char *end_name = strrchr(symbollist[i], ')');

        if (begin_name && end_name && begin_name < end_name) {
            char *begin_offset = strrchr(symbollist[i], '+');

            *begin_name++ = '\0';
            *end_name = '\0';

            // check whether we have offset
            if (begin_offset && begin_name <= begin_offset && begin_offset < end_name) {
                *begin_offset++ = '\0';
            } else {
                begin_offset = (char *) "?";
            }

            // check whether we have name
            if (strlen(begin_name) == 0) {
                begin_name = (char *) "???";
            }

            int status;
            char *ret = abi::__cxa_demangle(begin_name, funcname, &funcnamesize, &status);

            if (status == 0) {
                funcname = ret; // use possibly realloc()-ed string
                print_func("  [%010p] %s : %s+%s\n", addrlist[i], symbollist[i], funcname, begin_offset);
            } else {
                // demangling failed. Output function name as a C function with no arguments.
                print_func("  [%010p] %s : %s()+%s\n", addrlist[i], symbollist[i], begin_name, begin_offset);
            }
        } else {
            // couldn't parse the line? print the whole line.
            print_func("  %s\n", symbollist[i]);
        }
    }

    free(funcname);
    free(symbollist);
}
#endif // CONFIG_WIN32

namespace s2e {

std::string compress_file(const std::string &path) {
    // Simply call the system's gzip.
    std::stringstream ss;
    ss << "gzip \"" << path << "\"";
    int sret = system(ss.str().c_str());
    if (sret == -1) {
        return path;
    }

    // Check that the file was compressed
    llvm::SmallString<128> compressed(path);
    llvm::sys::path::replace_extension(compressed, "gz");

    if (llvm::sys::fs::exists(compressed)) {
        unlink(path.c_str());
        return compressed.c_str();
    }

    return path;
}

bool ReadLines(const std::string &file, std::vector<std::string> &lines, bool doTrim) {
    std::ifstream fs(file);

    if (!fs.is_open()) {
        return false;
    }

    std::string line;

    while (std::getline(fs, line)) {
        if (doTrim) {
            line = trim(line);
        }
        lines.push_back(line);
    }

    fs.close();
    return true;
}
} // namespace s2e
