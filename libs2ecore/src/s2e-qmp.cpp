///
/// Copyright (C) 2016, Cyberhaven
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

#include <boost/asio.hpp>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <string>

#include <qapi/qmp/qjson.h>
#include <qapi/qmp/qstring.h>
#include <s2e/monitor.h>

namespace s2e {

class S2EQMPClient {
private:
    std::string m_host;
    std::string m_port;

    boost::asio::io_service m_io_service;
    boost::asio::ip::tcp::socket m_socket;

    S2EQMPClient() : m_socket(m_io_service) {
    }

public:
    S2EQMPClient(const std::string &hostPort);
    bool connect();
    void emitJson(QObject *obj);
    bool ready() const;
};

S2EQMPClient::S2EQMPClient(const std::string &hostPort) : m_socket(m_io_service) {
    // default port
    m_host = hostPort;
    m_port = "1234";

    std::size_t colon = hostPort.find(':');
    if (colon != std::string::npos) {
        m_host = hostPort.substr(0, colon);
        m_port = hostPort.substr(colon + 1);
    }
}

bool S2EQMPClient::connect() {
    using namespace boost::asio::ip;

    std::cout << "QMP client connecting to " << m_host << ":" << m_port << "\n";

    try {
        tcp::resolver resolver(m_io_service);
        tcp::resolver::query query(m_host, m_port);
        tcp::resolver::iterator iter = resolver.resolve(query);

        m_socket.connect(*iter);

    } catch (std::exception &e) {
        std::cerr << "Exception while connecting to the QMP server: " << e.what() << "\n";
        return false;
    }

    return true;
}

void S2EQMPClient::emitJson(QObject *obj) {
    auto json = qobject_to_json(obj);

    std::stringstream data;
    data << json->str << "\n";
    g_string_free(json, true);
    qobject_unref(obj);

    try {
        boost::asio::write(m_socket, boost::asio::buffer(data.str().c_str(), data.str().length()));
    } catch (std::exception &e) {
        std::cerr << "s2e-qmp: could not write to socket\n";
        m_socket.close();
    }
}

bool S2EQMPClient::ready() const {
    return m_socket.is_open();
}
} // namespace s2e

static s2e::S2EQMPClient *s_client = nullptr;

extern "C" {

static int monitor_init_internal(const char *host_port) {
    s_client = new s2e::S2EQMPClient(host_port);
    if (!s_client->connect()) {
        return -1;
    }

    return 0;
}

int monitor_init(void) {
    const char *host_port = getenv("S2E_QMP_SERVER");
    if (!host_port) {
        // This var is optional, don't fail
        return 0;
    }

    return monitor_init_internal(host_port);
}

void monitor_close(void) {
    if (s_client) {
        delete s_client;
    }
}

void monitor_emit_json(QObject *object) {
    if (!s_client) {
        qobject_unref(object);
        return;
    }

    s_client->emitJson(object);
}

int monitor_ready(void) {
    if (!s_client) {
        return 0;
    }

    return s_client->ready();
}

int monitor_cur_is_qmp(void) {
    if (!s_client) {
        return 0;
    }

    return 1;
}

void monitor_printf(Monitor *mon, const char *fmt, ...) {
    printf("%s not implemented\n", __FUNCTION__);
}

void monitor_vprintf(Monitor *mon, const char *fmt, va_list ap) {
    vprintf(fmt, ap);
}
}
