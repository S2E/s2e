///
/// Copyright (C) 2015-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
