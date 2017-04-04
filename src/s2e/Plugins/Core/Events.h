///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_QMUEVENTS_H
#define S2E_PLUGINS_QMUEVENTS_H

extern "C" {

#include <s2e/monitor.h>

#include "qdict.h"
#include "qint.h"
#include "qobject.h"
}

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

        foreach2 (it, results.begin(), results.end()) { qdict_put_obj(pluginData, (*it).first, (*it).second); }

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
        QObject *plg = qdict_get(command, pluginName);
        if (!plg) {
            return NULL;
        }

        return qobject_to_qdict(plg);
    }

    static void requestSessionId() {
        QDict *dict = qdict_new();
        qdict_put_obj(dict, "get-session-id", QOBJECT(qint_from_int(0)));
        monitor_emit_json(QOBJECT(dict));
    }

    static void printDict(const Plugin *p, const QDict *dict) {
        llvm::raw_ostream &os = p->getDebugStream() << "\n";

        const QDictEntry *ent = qdict_first(dict);
        int idx = 0;
        for (ent = qdict_first(dict); ent; ent = qdict_next(dict, ent), ++idx) {
            const char *name = qdict_entry_key(ent);
            const QObject *value = qdict_entry_value(ent);

            const QInt *i = qobject_to_qint(value);
            if (i) {
                os << name << ": " << hexval(i->value) << " ";
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
