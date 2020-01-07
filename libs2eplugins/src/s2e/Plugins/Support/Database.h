///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_DATABASE_H
#define S2E_PLUGINS_DATABASE_H

#include <map>
#include <memory>
#include <s2e/Plugin.h>
#include <string>

namespace soci {
class session;
}

namespace s2e {
namespace plugins {

class Database : public Plugin {
    S2E_PLUGIN

public:
    Database(S2E *s2e) : Plugin(s2e) {
    }
    void initialize();

    soci::session &session() {
        return session("default");
    }

    soci::session &session(const std::string &name) {
        try {
            return m_sessions.at(name);
        } catch (std::out_of_range &) {
            getWarningsStream() << "Database " << name << " is not configured!\n";
            exit(-1);
        }
    }

    static std::string escapeBytea(soci::session &session, const std::vector<uint8_t> &data);

private:
    std::map<std::string, soci::session> m_sessions;

    void onProcessFork(bool prefork, bool, unsigned);

}; // class Database

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_DATABASE_H
