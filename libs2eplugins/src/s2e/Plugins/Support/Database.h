///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
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
