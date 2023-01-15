///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016-2019, Cyberhaven
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

#ifndef __MODULE_EXECUTION_DETECTOR_H_

#define __MODULE_EXECUTION_DETECTOR_H_

#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/Core/Vmi.h>
#include <s2e/Plugins/OSMonitors/Support/ITracker.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>

#include <inttypes.h>

#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index_container.hpp>

namespace s2e {
namespace plugins {

class OSMonitor;

///
/// \brief Represents one configuration entry
///
struct ModuleExecutionCfg {
    unsigned index;
    std::string id;
    std::string moduleName;
};

struct modbyid_t {};
struct modbyname_t {};

typedef boost::multi_index_container<
    ModuleExecutionCfg,
    boost::multi_index::indexed_by<
        boost::multi_index::ordered_unique<boost::multi_index::tag<modbyid_t>,
                                           BOOST_MULTI_INDEX_MEMBER(ModuleExecutionCfg, std::string, id)>,
        boost::multi_index::ordered_unique<boost::multi_index::tag<modbyname_t>,
                                           BOOST_MULTI_INDEX_MEMBER(ModuleExecutionCfg, std::string, moduleName)>>>
    ConfiguredModules;

typedef ConfiguredModules::index<modbyid_t>::type ConfiguredModulesById;
typedef ConfiguredModules::index<modbyname_t>::type ConfiguredModulesByName;

///
/// \brief The ModuleExecutionDetector plugin allows users to specify a list
/// of modules to track.
///
/// This plugin lets other plugins to:
/// - be notified when execution enters or leaves a specific module.
/// - be notified when the DBT translates code that belongs to a specific module.
///
/// A sample configuration looks like this:
///
/// \code{.lua}
/// pluginsConfig.ModuleExecutionDetector = {
///     mod_0 = {
///         moduleName = "fastfat2.sys",
///     },
///
///     trackExecution=true,
/// }
/// \endcode
///
/// It is possible to set trackExecution to false in order to decrease the overhead,
/// at the expense of not being notified when execution enters or leaves a configured
/// module.
class ModuleExecutionDetector : public Plugin, public ITracker {
    S2E_PLUGIN

public:
    ///
    /// \brief onModuleTransition is emitted when execution leaves one module
    /// and enters another one.
    ///
    sigc::signal<void, S2EExecutionState *, ModuleDescriptorConstPtr /* previousModule */,
                 ModuleDescriptorConstPtr /* nextModule */
                 >
        onModuleTransition;

    ///
    /// \brief onModuleTranslateBlockStart is emmitted when the DBT starts
    /// translating a block that belongs to a configured module.
    ///
    sigc::signal<void, ExecutionSignal *, S2EExecutionState *, const ModuleDescriptor &, TranslationBlock *,
                 uint64_t /* block PC */
                 >
        onModuleTranslateBlockStart;

    ///
    /// \brief onModuleTranslateBlockEnd is emitted for each exit point of a
    /// configured module's translation block.
    ///
    sigc::signal<void, ExecutionSignal *, S2EExecutionState *, const ModuleDescriptor &, TranslationBlock *,
                 uint64_t /* ending instruction pc */, bool /* static target is valid */,
                 uint64_t /* static target pc */
                 >
        onModuleTranslateBlockEnd;

    ///
    /// \brief onModuleTranslateBlockComplete is emitted when the DBT finishes
    /// translating a block for a configured module.
    ///
    sigc::signal<void, S2EExecutionState *, const ModuleDescriptor &, TranslationBlock *,
                 uint64_t /* ending instruction pc */
                 >
        onModuleTranslateBlockComplete;

    ///
    /// \brief onModuleLoad is emitted when a configured module is loaded.
    ///
    /// This signal works like onModuleLoad in OSMonitor, except that it filters
    /// out any module that was not specified in ModuleExecutionDetector's config
    /// section. Plugins may subscribe to this signal if they only care about
    /// modules that the user configured.
    ///
    sigc::signal<void, S2EExecutionState *, const ModuleDescriptor &> onModuleLoad;

    sigc::signal<void, S2EExecutionState *> onConfigChange;
    bool isTrackedPc(S2EExecutionState *state, uint64_t pc);
    bool isTrackingConfigured(S2EExecutionState *state);

private:
    OSMonitor *m_monitor;
    Vmi *m_vmi;
    ModuleMap *m_modules;
    ConfiguredModules m_configuredModules;

    bool m_trackExecution;

    void initializeConfiguration();

    void onMonitorLoad(S2EExecutionState *state);

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t endPc,
                             bool staticTarget, uint64_t targetPc);

    void onTranslateBlockComplete(S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onExecution(S2EExecutionState *state, uint64_t pc, ModuleDescriptorConstPtr currentModule);

    void exceptionListener(S2EExecutionState *state, unsigned intNb, uint64_t pc);

    void moduleLoadListener(S2EExecutionState *state, const ModuleDescriptor &module);

    bool exists(const std::string &id, const std::string &name) const;

public:
    ModuleExecutionDetector(S2E *s2e) : Plugin(s2e) {
    }

    virtual ~ModuleExecutionDetector(){};

    void initialize();

    ModuleDescriptorConstPtr getModule(S2EExecutionState *state, uint64_t pc);
    ModuleDescriptorConstPtr getCurrentDescriptor(S2EExecutionState *state) const;
    ModuleDescriptorConstPtr getDescriptor(S2EExecutionState *state, uint64_t pc) const;

    const std::string *getModuleId(const ModuleDescriptor &desc, unsigned *index = nullptr) const;
    bool getModuleConfig(const std::string &id, ModuleExecutionCfg &cfg) const;
    bool isModuleConfigured(const std::string &moduleId) const;
    bool isModuleNameConfigured(const std::string &moduleName) const;
};

} // namespace plugins
} // namespace s2e

#endif
