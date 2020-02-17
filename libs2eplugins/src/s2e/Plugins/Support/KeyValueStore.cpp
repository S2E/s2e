///
/// Copyright (C) 2013-2015, Dependable Systems Laboratory, EPFL
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

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <boost/asio.hpp>
#include <klee/Common.h>

#include "KeyValueStore.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(KeyValueStore, "KeyValueStore S2E plugin", "", );

void KeyValueStore::initialize() {
    m_server = s2e()->getConfig()->getString(getConfigKey() + ".server", "localhost");
    m_port = s2e()->getConfig()->getInt(getConfigKey() + ".port", 11211);

    std::string serverType = s2e()->getConfig()->getString(getConfigKey() + ".type", "local");
    if (serverType == "native") {
        m_server_type = ST_NATIVE;
        connectNative();
        getDebugStream() << "KeyValueStore: creating native kvs session " << m_session_id << "\n";
    } else if (serverType == "memcached") {
        std::stringstream ss;
        ss << rand() << "_";
        m_session_id = ss.str();

        getDebugStream() << "KeyValueStore: creating memcached session " << m_session_id << "\n";
        m_server_type = ST_MEMCACHED;
        connectMemcached();
    } else if (serverType == "local") {
        m_server_type = ST_LOCAL;
    } else {
        getWarningsStream() << "KeyValueStore: unknown server type " << serverType << "\n";
        exit(-1);
    }

    s2e()->getCorePlugin()->onProcessFork.connect(sigc::mem_fun(*this, &KeyValueStore::onProcessFork));
}

bool KeyValueStore::syncReadUntil(boost::asio::streambuf &data, const char *str) {
    try {
        boost::system::error_code ec;
        do {
            boost::asio::read_until(m_socket, data, str, ec);
            if (ec != boost::system::errc::interrupted) {
                if (ec != boost::system::errc::success) {
                    std::cerr << "KeyValueStore::syncRead: exception while communicating with the external solver: "
                              << ec << "\n";
                    return false;
                }
            }
        } while (ec == boost::system::errc::interrupted);

        return true;
    } catch (std::exception &e) {
        // TODO: handle interrupted syscalls
        std::cerr << "KeyValueStore::syncRead: exception while communicating with the external solver: " << e.what()
                  << "\n";
        return false;
    }
}

void KeyValueStore::connectNative() {
    try {
        std::stringstream sp;
        sp << m_port;

        boost::asio::ip::tcp::resolver resolver(m_io_service);
        boost::asio::ip::tcp::resolver::query query(m_server, sp.str());
        boost::asio::ip::tcp::resolver::iterator iter = resolver.resolve(query);

        m_socket.connect(*iter);

        std::stringstream ss;

        if (m_session_id.size() == 0) {
            ss << "get-session-id\n";
            boost::asio::write(m_socket, boost::asio::buffer(ss.str().c_str(), ss.str().length()));

            boost::asio::streambuf streamBuf;
            if (!syncReadUntil(streamBuf, "\n")) {
                exit(-1);
            }

            std::istream is(&streamBuf);
            std::getline(is, m_session_id);

            getDebugStream() << "KeyValueStore: got session id " << m_session_id << "\n";
        } else {
            ss << "set-session-id " << m_session_id << "\n";
            boost::asio::write(m_socket, boost::asio::buffer(ss.str().c_str(), ss.str().length()));
        }

    } catch (std::exception &e) {
        std::cerr << "Exception while connecting to the key value store service: " << e.what() << "\n";
        exit(-1);
    }
}

void KeyValueStore::connectMemcached() {
    memcached_return rc;

    m_cache = nullptr;
    m_cache_servers = nullptr;
    m_cache_servers = memcached_server_list_append(m_cache_servers, m_server.c_str(), m_port, &rc);
    m_cache = memcached_create(nullptr);

    rc = memcached_server_push(m_cache, m_cache_servers);

    if (rc != MEMCACHED_SUCCESS) {
        getWarningsStream() << "KeyValueStore: could not initialize memcached - " << memcached_strerror(m_cache, rc)
                            << "\n";
        exit(-1);
    }

    if (!put(m_session_id + "init", "1")) {
        getWarningsStream() << "KeyValueStore: could not connect to memcached\n";
        exit(-1);
    }
}

void KeyValueStore::onProcessFork(bool preFork, bool isChild, unsigned parentProcId) {
    if (m_server_type == ST_MEMCACHED) {
        if (preFork) {
            memcached_free(m_cache);
        } else {
            connectMemcached();
        }
    } else if (m_server_type == ST_NATIVE) {
        if (preFork) {
            m_socket.close();
        } else {
            connectNative();
        }
    }
}

bool KeyValueStore::getProperty(S2EExecutionState *state, const std::string &name, std::string &value) {
    return get(state, name, value);
}

bool KeyValueStore::setProperty(S2EExecutionState *state, const std::string &name, const std::string &value) {
    return put(state, name, value);
}

bool KeyValueStore::put(S2EExecutionState *state, const std::string &key, const std::string &val) {
    DECLARE_PLUGINSTATE(KeyValueStoreState, state);
    bool ret = plgState->put(key, val);
    onLocalPut.emit(state, key, val, ret);
    return ret;
}

bool KeyValueStore::get(S2EExecutionState *state, const std::string &key, std::string &val) {
    DECLARE_PLUGINSTATE(KeyValueStoreState, state);
    return plgState->get(key, val);
}

bool KeyValueStore::put(const std::string &key, const std::string &value) {
    if (m_server_type == ST_MEMCACHED) {
        memcached_return rc;
        std::string skey = m_session_id + key;
        rc = memcached_set(m_cache, skey.c_str(), skey.size(), value.c_str(), value.size(), 0, 0);

        return rc == MEMCACHED_SUCCESS;
    } else if (m_server_type == ST_NATIVE) {
        std::stringstream ss;
        ss << "set-value " << key << "=" << value << "\n";
        boost::asio::write(m_socket, boost::asio::buffer(ss.str().c_str(), ss.str().length()),
                           boost::asio::transfer_all());
        return true;
    } else if (m_server_type == ST_LOCAL) {
        m_global_storage[key] = value;
        return true;
    } else {
        pabort("Can't happen");
    }
}

bool KeyValueStore::put(const std::string &key, const std::string &val, bool &exists) {
    std::string dummy;
    lock();
    exists = get(key, dummy);
    bool ret = put(key, val);
    unlock();
    return ret;
}

bool KeyValueStore::get(const std::string &key, std::string &val) {
    if (m_server_type == ST_MEMCACHED) {
        memcached_return rc;
        size_t read_value_length = 0;
        uint32_t flags = 0;

        std::string skey = m_session_id + key;
        char *ret = memcached_get(m_cache, skey.c_str(), skey.size(), &read_value_length, &flags, &rc);
        if (!ret) {
            return false;
        }

        val = ret;
        free(ret);
        return (rc == MEMCACHED_SUCCESS);
    } else if (m_server_type == ST_NATIVE) {
        std::stringstream ss;
        ss << "get-value " << key << "\n";
        boost::asio::write(m_socket, boost::asio::buffer(ss.str().c_str(), ss.str().length()));

        boost::asio::streambuf streamBuf;
        if (!syncReadUntil(streamBuf, "\n")) {
            return false;
        }

        std::istream is(&streamBuf);
        std::getline(is, val);

        return val.size() != 0;
    } else if (m_server_type == ST_LOCAL) {
        KV::const_iterator it = m_global_storage.find(key);
        if (it == m_global_storage.end()) {
            return false;
        }
        val = (*it).second;
        return true;
    } else {
        pabort("Can't happen");
    }
}

void KeyValueStore::lock() {
    m_lock.acquire();
}

void KeyValueStore::unlock() {
    m_lock.release();
}

KeyValueStore::~KeyValueStore() {
    if (m_server_type == ST_MEMCACHED) {
        if (m_cache) {
            memcached_free(m_cache);
        }
    }
}

void KeyValueStore::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    S2E_KVSTORE_PLUGIN_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "KeyValueStore: mismatched S2E_KVSTORE_PLUGIN_COMMAND size "
                                 << "(got " << guestDataSize << " expected " << sizeof(command) << ")\n";
        return;
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "KeyValueStore: could not read transmitted data\n";
        return;
    }

    std::string key;
    if (command.Command & KVS_INTEGER_KEY) {
        std::stringstream ss;
        ss << command.IntegerKey;
        key = ss.str();
    } else {
        if (command.KeyAddress && !state->mem()->readString(command.KeyAddress, key)) {
            getWarningsStream(state) << "KeyValueStore: could not read the key\n";
            return;
        }
    }

    std::string value, dummy;

    switch (command.Command & ~KVS_INTEGER_KEY) {
        case KVS_PUT_STRING: {
            if (!state->mem()->readString(command.ValueAddress, value, command.ValueSize)) {
                getWarningsStream(state) << "KeyValueStore: could not read the value for key " << key << "\n";
                unlock();
                return;
            }

            if (command.Local) {
                command.NewKey = !get(state, key, dummy);
                command.Success = put(state, key, value);
            } else {
                bool exists;
                command.Success = put(key, value, exists);
                command.NewKey = !exists;
            }
        } break;

        case KVS_GET_STRING: {
            if (command.Local) {
                command.Success = get(state, key, value);
            } else {
                command.Success = get(key, value);
            }

            if (command.Success) {
                unsigned len = value.size() + 1;
                unsigned max = command.ValueSize < len ? command.ValueSize : len;
                command.Success = state->mem()->write(command.ValueAddress, value.c_str(), max);
            }
        } break;

        case KVS_PUT_INT: {
            std::stringstream ss;
            ss << command.IntegerValue;

            if (command.Local) {
                command.NewKey = !get(state, key, dummy);
                command.Success = put(state, key, ss.str());
            } else {
                bool exists;
                command.Success = put(key, ss.str(), exists);
                command.NewKey = !exists;
            }
        } break;

        case KVS_GET_INT: {
            if (command.Local) {
                command.Success = get(state, key, value);
            } else {
                command.Success = get(key, value);
            }

            if (command.Success) {
                command.IntegerValue = strtol(value.c_str(), nullptr, 0);
            }
        } break;

        case KVS_LOCK: {
            lock();
            command.Success = 1;
        } break;

        case KVS_UNLOCK: {
            unlock();
            command.Success = 1;
        } break;

        default: {
            getWarningsStream(state) << "KeyValueStore: unknown command " << command.Command << "\n";
        } break;
    }

    if (!state->mem()->write(guestDataPtr, &command, guestDataSize)) {
        getDebugStream(state) << "KeyValueStore: could not write back result to guest\n";
    }
}

/*********************************************************/

KeyValueStoreState::KeyValueStoreState() {
}

KeyValueStoreState::~KeyValueStoreState() {
}

KeyValueStoreState *KeyValueStoreState::clone() const {
    return new KeyValueStoreState(*this);
}

PluginState *KeyValueStoreState::factory(Plugin *p, S2EExecutionState *s) {
    return new KeyValueStoreState();
}

bool KeyValueStoreState::put(const std::string &key, const std::string &val) {
    m_storage[key] = val;
    return true;
}

bool KeyValueStoreState::get(const std::string &key, std::string &val) {
    KV::const_iterator it = m_storage.find(key);
    if (it == m_storage.end()) {
        return false;
    }
    val = (*it).second;
    return true;
}

} // namespace plugins
} // namespace s2e
