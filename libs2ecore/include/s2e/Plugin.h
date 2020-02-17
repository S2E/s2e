///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
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

#ifndef S2E_PLUGIN_H
#define S2E_PLUGIN_H

#include <fsigc++/fsigc++.h>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <llvm/Support/raw_ostream.h>

#include "Logging.h"

namespace s2e {

class S2E;
struct PluginInfo;
class PluginState;
class S2EExecutionState;

class Plugin {
private:
    S2E *m_s2e;
    LogLevel m_logLevel;
    llvm::raw_ostream *m_nullOutput;

protected:
    mutable PluginState *m_CachedPluginState;
    mutable S2EExecutionState *m_CachedPluginS2EState;

public:
    Plugin(S2E *s2e) : m_s2e(s2e), m_CachedPluginState(nullptr), m_CachedPluginS2EState(nullptr) {
    }

    virtual ~Plugin() {
    }

    LogLevel getLogLevel() {
        return m_logLevel;
    }

    /** Return associated S2E instance. */
    S2E *s2e() {
        return m_s2e;
    }
    const S2E *s2e() const {
        return m_s2e;
    }

    /** Initialize plugin. This function is called on initialization
        after all plugin instances have already been instantiated. */
    virtual void initialize();

    /** Reads config file and sets log level */
    void configureLogLevel();

    /** Return PluginInfo for this class. Defined by S2E_PLUGIN macro */
    virtual const PluginInfo *getPluginInfo() const = 0;

    /** Return configuration key for this plugin */
    const std::string &getConfigKey() const;

    PluginState *getPluginState(S2EExecutionState *s, PluginState *(*f)(Plugin *, S2EExecutionState *) ) const;

    void refresh() {
        m_CachedPluginS2EState = nullptr;
        m_CachedPluginState = nullptr;
    }

    virtual bool getProperty(S2EExecutionState *state, const std::string &name, std::string &value) {
        return false;
    }

    virtual bool setProperty(S2EExecutionState *state, const std::string &name, const std::string &value) {
        return false;
    }

    llvm::raw_ostream &getDebugStream(S2EExecutionState *state = nullptr) const;
    llvm::raw_ostream &getInfoStream(S2EExecutionState *state = nullptr) const;
    llvm::raw_ostream &getWarningsStream(S2EExecutionState *state = nullptr) const;
    llvm::raw_ostream &getNullStream(S2EExecutionState *state = nullptr) const {
        return *m_nullOutput;
    }
};

#define DECLARE_PLUGINSTATE_P(plg, c, execstate) \
    c *plgState = static_cast<c *>(plg->getPluginState(execstate, &c::factory))

#define DECLARE_PLUGINSTATE(c, execstate) c *plgState = static_cast<c *>(getPluginState(execstate, &c::factory))

#define DECLARE_PLUGINSTATE_N(c, name, execstate) c *name = static_cast<c *>(getPluginState(execstate, &c::factory))

#define DECLARE_PLUGINSTATE_CONST(c, execstate) \
    const c *plgState = static_cast<c *>(getPluginState(execstate, &c::factory))

#define DECLARE_PLUGINSTATE_NCONST(c, name, execstate) \
    const c *name = static_cast<c *>(getPluginState(execstate, &c::factory))

class PluginState {
public:
    virtual ~PluginState(){};
    virtual PluginState *clone() const = 0;
};

struct PluginInfo {
    /** Unique name of the plugin */
    std::string name;

    /** Human-readable description of the plugin */
    std::string description;

    /** Name of a plugin function (only one plugin is allowed for each function) */
    std::string functionName;

    /** Dependencies of this plugin */
    std::vector<std::string> dependencies;

    /** Configuration key for this plugin */
    std::string configKey;

    /** A function to create a plugin instance */
    Plugin *(*instanceCreator)(S2E *);
};

typedef struct PluginGraphData {
    const PluginInfo *info;
} PluginGraphData;

class PluginsFactory {
private:
    typedef std::map<std::string, const PluginInfo *> PluginsMap;
    PluginsMap m_pluginsMap;

    std::vector<const PluginInfo *> m_pluginsList;

public:
    PluginsFactory();

    void registerPlugin(const PluginInfo *pluginInfo);

    const std::vector<const PluginInfo *> &getPluginInfoList() const;
    const PluginInfo *getPluginInfo(const std::string &name) const;

    Plugin *createPlugin(S2E *s2e, const std::string &name) const;
};

class CompiledPlugin {
public:
    typedef std::set<const PluginInfo *> CompiledPlugins;

private:
    static CompiledPlugins *s_compiledPlugins;

    CompiledPlugin();

public:
    CompiledPlugin(const PluginInfo *info) {
        if (!s_compiledPlugins) {
            s_compiledPlugins = new CompiledPlugins();
        }
        s_compiledPlugins->insert(info);
    }

    static CompiledPlugins *getPlugins() {
        return s_compiledPlugins;
    }
};

/** Should be put at the beginning of any S2E plugin */
#define S2E_PLUGIN                                    \
private:                                              \
    static const char s_pluginDeps[][64];             \
    static const PluginInfo s_pluginInfo;             \
                                                      \
public:                                               \
    virtual const PluginInfo *getPluginInfo() const { \
        return &s_pluginInfo;                         \
    }                                                 \
    static const PluginInfo *getPluginInfoStatic() {  \
        return &s_pluginInfo;                         \
    }                                                 \
                                                      \
private:

/** Defines an S2E plugin. Should be put in a cpp file.
    NOTE: use S2E_NOOP from Utils.h to pass multiple dependencies */
#define S2E_DEFINE_PLUGIN(className, description, functionName, ...)                                        \
    const char className::s_pluginDeps[][64] = {__VA_ARGS__};                                               \
    const PluginInfo className::s_pluginInfo = {                                                            \
        #className,                                                                                         \
        description,                                                                                        \
        functionName,                                                                                       \
        std::vector<std::string>(className::s_pluginDeps,                                                   \
                                 className::s_pluginDeps +                                                  \
                                     sizeof(className::s_pluginDeps) / sizeof(className::s_pluginDeps[0])), \
        "pluginsConfig['" #className "']",                                                                  \
        _pluginCreatorHelper<className>};                                                                   \
    static CompiledPlugin s_##className(className::getPluginInfoStatic())

template <class C> Plugin *_pluginCreatorHelper(S2E *s2e) {
    return new C(s2e);
}

inline const std::string &Plugin::getConfigKey() const {
    return getPluginInfo()->configKey;
}

} // namespace s2e

#endif // S2E_PLUGIN_H
