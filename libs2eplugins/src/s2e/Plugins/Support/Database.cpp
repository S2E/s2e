///
/// Copyright (C) 2015-2016, Dependable Systems Laboratory, EPFL
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

#include "Database.h"

#include <s2e/ConfigFile.h>
#include <s2e/CorePlugin.h>
#include <s2e/S2E.h>

#include <soci/postgresql/soci-postgresql.h>
#include <soci/soci.h>

#include <libpq-fe.h>

extern "C" {
void register_factory_postgresql();
}

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(Database, "Databse support plugin", "");

void Database::initialize() {
    // Register soci backends that we want to support
    register_factory_postgresql();

    ConfigFile *cfg = s2e()->getConfig();
    ConfigFile::string_list databases = cfg->getListKeys(getConfigKey());

    if (databases.empty()) {
        getWarningsStream() << "no databases configured!\n";
    }

    for (auto &database : databases) {
        std::string connection_string = cfg->getString(getConfigKey() + '.' + database);

        soci::session &db = m_sessions
                                .emplace(std::piecewise_construct, std::forward_as_tuple(database),
                                         std::forward_as_tuple(connection_string))
                                .first->second;
        db << "SET AUTOCOMMIT TO ON"; // FIXME: make this configurable
    }

    s2e()->getCorePlugin()->onProcessFork.connect(sigc::mem_fun(*this, &Database::onProcessFork));
}

void Database::onProcessFork(bool prefork, bool, unsigned) {
    if (prefork) {
        for (auto &it : m_sessions)
            it.second.close();
    } else {
        for (auto &it : m_sessions)
            it.second.reconnect();
    }
}

std::string Database::escapeBytea(soci::session &session, const std::vector<uint8_t> &data) {
    if (session.get_backend_name() == "postgresql") {
        PGconn *conn = static_cast<soci::postgresql_session_backend *>(session.get_backend())->conn_;

        size_t out_length = 0;
        unsigned char *out_bytes = PQescapeByteaConn(conn, data.data(), data.size(), &out_length);

        std::string out((const char *) out_bytes);
        PQfreemem(out_bytes);

        return out;
    } else {
        llvm::errs() << "Database::escapeBytea() is not supported on " << session.get_backend_name() << " yet\n";
        abort();
    }
}

} // namespace plugins
} // namespace s2e
