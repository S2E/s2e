///
/// Copyright (C) 2013-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2015, Cyberhaven
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

#ifndef S2E_PLUGINS_KeyValueStore_H
#define S2E_PLUGINS_KeyValueStore_H

#include <libmemcached/memcached.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Synchronization.h>

#include <boost/asio.hpp>

namespace s2e {
namespace plugins {

typedef enum _S2E_KVSTORE_PLUGIN_COMMANDS {
    KVS_PUT_STRING,
    KVS_GET_STRING,
    KVS_PUT_INT,
    KVS_GET_INT,
    KVS_LOCK,
    KVS_UNLOCK,
    KVS_INTEGER_KEY = 0x80000000
} S2E_KVSTORE_PLUGIN_COMMANDS;

typedef struct _S2E_KVSTORE_PLUGIN_COMMAND {
    S2E_KVSTORE_PLUGIN_COMMANDS Command;

    union {
        /* Pointer to the string that will be used as a key */
        uint64_t KeyAddress;

        /* Integer key */
        uint64_t IntegerKey;
    };

    /* Key/Value should be put in the current state */
    uint64_t Local;

    /* Guest address where to store/get the value */
    union {
        uint64_t ValueAddress;
        uint64_t IntegerValue;
    };

    /* Size of the value in bytes */
    uint64_t ValueSize;

    /* Results */

    /* Key did not exist before */
    uint64_t NewKey;

    /* Success status of the command */
    uint64_t Success;
} S2E_KVSTORE_PLUGIN_COMMAND;

/**
 * The KeyValueStore plugin allows to store key/value pairs in memcached.
 * This allows to easily share information between multiple instances of S2E.
 * One can use memcached or the native server (in KeyValueStore.py).
 * The native store supports sessions. It is also possible to use the local
 * store, without any server (e.g., in single-core mode).
 */
class KeyValueStore : public Plugin, public IPluginInvoker {
    S2E_PLUGIN

    enum ServerType { ST_MEMCACHED, ST_NATIVE, ST_LOCAL };

public:
    sigc::signal<void, S2EExecutionState *, const std::string & /* key */, const std::string & /* value */,
                 bool /* success */>
        onLocalPut;

    KeyValueStore(S2E *s2e) : Plugin(s2e), m_socket(m_io_service) {
    }
    virtual ~KeyValueStore();

    void initialize();

    bool put(const std::string &key, const std::string &val, bool &exists);
    bool put(const std::string &key, const std::string &val);
    bool get(const std::string &key, std::string &val);

    bool put(S2EExecutionState *state, const std::string &key, const std::string &val);
    bool get(S2EExecutionState *state, const std::string &key, std::string &val);

    bool getProperty(S2EExecutionState *state, const std::string &name, std::string &value);
    bool setProperty(S2EExecutionState *state, const std::string &name, const std::string &value);

    void lock();
    void unlock();

    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);

private:
    boost::asio::io_service m_io_service;
    boost::asio::ip::tcp::socket m_socket;

    std::string m_session_id;
    std::string m_server;
    uint16_t m_port;

    ServerType m_server_type;

    memcached_server_st *m_cache_servers;
    memcached_st *m_cache;

    typedef std::map<std::string, std::string> KV;
    KV m_global_storage;

    S2ESynchronizedObject<uint64_t> m_lock;

    void connectMemcached();
    void connectNative();
    bool syncReadUntil(boost::asio::streambuf &data, const char *str);
    void onProcessFork(bool preFork, bool isChild, unsigned parentProcId);
};

class KeyValueStoreState : public PluginState {
private:
    typedef std::map<std::string, std::string> KV;
    KV m_storage;

public:
    KeyValueStoreState();
    virtual ~KeyValueStoreState();
    virtual KeyValueStoreState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    bool put(const std::string &key, const std::string &val);
    bool get(const std::string &key, std::string &val);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_KeyValueStore_H
