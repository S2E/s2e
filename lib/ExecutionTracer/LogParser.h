///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2ETOOLS_EXECTRACER_LOGPARSER_H
#define S2ETOOLS_EXECTRACER_LOGPARSER_H

#include <fsigc++/fsigc++.h>
#include <map>
#include <s2e/Plugins/ExecutionTracers/TraceEntries.h>
#include <set>
#include <stdio.h>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace s2etools {

/**
 *  Trace item processors must use this class if they with to store
 *  aggregated data along trace processing.
 */
class ItemProcessorState {
public:
    virtual ~ItemProcessorState(){};
    virtual ItemProcessorState *clone() const = 0;
};

// opaque references the registered trace processor
typedef std::map<void *, ItemProcessorState *> ItemProcessors;
typedef std::set<uint32_t> PathSet;

typedef ItemProcessorState *(*ItemProcessorStateFactory)();

class LogEvents {
public:
    sigc::signal<void, unsigned, const s2e::plugins::ExecutionTraceItemHeader &, void *> onEachItem;

    virtual ItemProcessorState *getState(void *processor, ItemProcessorStateFactory f) = 0;
    virtual ItemProcessorState *getState(void *processor, uint32_t pathId) = 0;
    virtual void getPaths(PathSet &s) = 0;

protected:
    virtual void processItem(unsigned itemEntry, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *data);

    LogEvents();
    virtual ~LogEvents();
};

class LogParser : public LogEvents {
private:
    struct LogFile {
#ifdef _WIN32
        HANDLE m_hFile;
        HANDLE m_hMapping;
#endif
        void *m_File;
        uint64_t m_size;

        LogFile() {
#ifdef _WIN32
            m_hFile = NULL;
            m_hMapping = NULL;
#endif
            m_File = NULL;
            m_size = 0;
        }
    };

    typedef std::vector<LogFile> LogFiles;

    LogFiles m_files;
    std::vector<uint8_t *> m_ItemAddresses;

    ItemProcessors m_ItemProcessors;
    void *m_cachedProcessor;
    ItemProcessorState *m_cachedState;

protected:
public:
    LogParser();
    virtual ~LogParser();

    bool parse(const std::vector<std::string> fileNames);
    bool parse(const std::string &file);
    bool getItem(unsigned index, s2e::plugins::ExecutionTraceItemHeader &hdr, void **data);

    virtual ItemProcessorState *getState(void *processor, ItemProcessorStateFactory f);
    virtual ItemProcessorState *getState(void *processor, uint32_t pathId);
    virtual void getPaths(PathSet &s);
};
}

#endif
