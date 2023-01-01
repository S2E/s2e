///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
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

#ifndef S2E_PLUGINS_QMUEVENTS_H
#define S2E_PLUGINS_QMUEVENTS_H

#include <s2e/monitor.h>

#include <qapi/qmp/qdict.h>
#include <qapi/qmp/qnum.h>
#include <qapi/qmp/qobject.h>

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Utils.h>

#include <vector>

namespace s2e {
namespace plugins {

struct Events {
    typedef std::vector<std::pair<const char *, QObject *>> PluginData;

    /**
     *  Puts the following structure into ret:
     *  "PluginName" : { }
     *  The structure { } is returned.
     */
    static QDict *createResult(const Plugin *p, QDict *ret) {
        const char *pluginName = p->getPluginInfo()->name.c_str();
        QDict *dict = qdict_new();
        qdict_put(ret, pluginName, dict);
        return dict;
    }

    /**
     * Emits the following structure:
     * {
         "s2e-event" : {
             "plugin0" : { ... },
             "plugin1" : { ... },
         }
     * }
     *
     * The name of the plugin and the plugin's specific data is passed
     * in the vector as a parameter.
     */
    static void emitQMPEvent(const Plugin *p, const PluginData &results) {
        QDict *s2e_event = qdict_new();
        QDict *allPluginData = qdict_new();
        QDict *pluginData = createResult(p, allPluginData);

        foreach2 (it, results.begin(), results.end()) {
            qdict_put_obj(pluginData, (*it).first, (*it).second);
        }

        qdict_put(s2e_event, "s2e-event", allPluginData);
        monitor_emit_json(QOBJECT(s2e_event));
    }

    static QDict *prepareData(const Plugin *p, QObject *data) {
        const char *pluginName = p->getPluginInfo()->name.c_str();
        QDict *plugin = qdict_new();
        qdict_put_obj(plugin, pluginName, data);
        return plugin;
    }

    static void prepareData(QDict *out, const Plugin *p, QObject *data) {
        const char *pluginName = p->getPluginInfo()->name.c_str();
        qdict_put_obj(out, pluginName, data);
    }

    static QDict *prepareEvent(const Plugin *p, QObject *data) {
        QDict *s2e_event = qdict_new();
        qdict_put(s2e_event, "s2e-event", prepareData(p, data));
        return s2e_event;
    }

    static void emitQMPEvent(const Plugin *p, QObject *data) {
        monitor_emit_json(QOBJECT(prepareEvent(p, data)));
    }

    /**
     * Given the following structure in command:
       {
         "plugin0" : { ... },
         "plugin1" : { ... },
       }
     *
     * Returns the one corresponding to the specified plugin.
     */
    static QDict *getPluginData(const Plugin *p, const QDict *command) {
        const char *pluginName = p->getPluginInfo()->name.c_str();
        return qdict_get_qdict(command, pluginName);
    }

    static void requestSessionId() {
        QDict *dict = qdict_new();
        qdict_put_obj(dict, "get-session-id", QOBJECT(qnum_from_int(0)));
        monitor_emit_json(QOBJECT(dict));
    }

    static void printDict(const Plugin *p, const QDict *dict) {
        llvm::raw_ostream &os = p->getDebugStream() << "\n";

        const QDictEntry *ent = qdict_first(dict);
        int idx = 0;
        for (ent = qdict_first(dict); ent; ent = qdict_next(dict, ent), ++idx) {
            const char *name = qdict_entry_key(ent);
            const auto value = qdict_entry_value(ent);

            const auto i = qobject_to(QNum, value);
            if (i) {
                os << name << ": " << hexval(qnum_get_uint(i)) << " ";
                if ((idx % 4) == 3) {
                    os << "\n";
                }
            }
        }

        os << "\n";
    }
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_QMUEVENTS_H
