///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2ETOOLS_LIBRARY_H

#define S2ETOOLS_LIBRARY_H

#include <map>
#include <set>
#include <string>
#include <vector>

#include <cinttypes>
#include <vmi/ExecutableFile.h>

namespace s2etools {

class ExecutableFile;
struct ModuleInstance;

class Library {
public:
    typedef std::map<std::string, vmi::ExecutableFile *> ModuleNameToExec;
    typedef std::vector<std::string> PathList;
    typedef std::set<std::string> StringSet;

private:
    PathList m_libpath;
    ModuleNameToExec m_libraries;
    StringSet m_badLibraries;

public:
    virtual ~Library();

    /// Add a library using a relative path.
    bool addLibrary(const std::string &libName);

    /// Add a library using an absolute path.
    bool addLibraryAbs(const std::string &libName);

    /// Get a library using a name.
    vmi::ExecutableFile *get(const std::string &name);

    void addPath(const std::string &s);
    void setPaths(const PathList &s);

    bool print(const std::string &modName, uint64_t loadBase, uint64_t imageBase, uint64_t pc, std::string &out,
               bool file, bool line, bool func);

    /// Helper function to quickly print debug info.
    bool print(const ModuleInstance *ni, uint64_t pc, std::string &out, bool file, bool line, bool func);
    bool getInfo(const ModuleInstance *ni, uint64_t pc, std::string &file, uint64_t &line, std::string &func);

    /// Cycles through the list of paths and attempts to find the specified
    /// library.
    bool findLibrary(const std::string &libName, std::string &abspath);
    bool findSuffixedModule(const std::string &moduleName, const std::string &suffix, std::string &path);
    bool findBasicBlockList(const std::string &moduleName, std::string &path);
    bool findDisassemblyListing(const std::string &moduleName, std::string &path);

    static uint64_t translatePid(uint64_t pid, uint64_t pc);
};

} // namespace s2etools

#endif
