#!/usr/bin/env python

# Copyright (C) 2013, Dependable Systems Laboratory, EPFL
# Copyright (C) 2017, Cyberhaven
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
Very simple in memory Key Value Store to be used by the S2E plugin.
All lines end with \n.

Usage:

    $ telnet ::1 1234
    > get-session-id
    1
    > set-value a=foo
    OK
    > quit

    $ telnet localhost 1234
    > set-session-id 1
    OK
    > get-value a
    foo
    > quit
"""
import os
import re
import sys
import socket
import logging
import asyncore


class KVStore(asyncore.dispatcher_with_send):
    """\
    Key Value Store (working in memory only).
    """

    sessions = {}
    sid = long(0)
    log = logging.getLogger("KVStore")

    def __init__(self, sock):
        asyncore.dispatcher_with_send.__init__(self, sock)
        self.session_id = None

    def handle_read(self):
        read = self.recv(8192)
        if read is None:
            self.close()
        read = read.strip()
        if len(read):
            for line in re.split(r"[\n]+[ \t]*", read):
                self.handle_command(line)

    def handle_command(self, line):
        self.log.debug("< %s" % repr(line))
        if line == "quit":
            self.close()
        elif line == "get-session-id":
            if self.session_id is None:
                self.session_id = self.get_session_id()
            self.sendLine(str(self.session_id))
        elif line.startswith("set-session-id "):
            cmd, args = re.split(r"\s+", line, 1)
            try:
                session_id = long(args)
                if self.has_session_id(session_id) and str(session_id) == args:
                    self.session_id = session_id
                    self.sendLine("OK")
                else:
                    self.sendLine("ERROR: Unknown session id")
            except ValueError, e:
                self.sendLine(repr(e))
        elif self.session_id is not None:
            error = False
            try:
                cmd, args = re.split(r"\s+", line, 1)
                if cmd == "get-value":
                    self.sendLine(self.get(args))
                elif cmd == "set-value":
                    key, value = re.split(r"=", args, 1)
                    self.set(key, value)
                    self.sendLine("OK")
                else:
                    error = True
            except ValueError, e:
                error = True

            if error:
                self.sendLine("ERROR: `get-value <key>` or `set-value "
                              "<key>=<value>` were expected")
        else:
            self.sendLine("ERROR: `get-session-id` or `set-session-id` "
                          "were expected")

    def sendLine(self, message):
        self.send("%s\n" % message)

    def send(self, data):
        self.log.debug("> %s" % repr(data))
        asyncore.dispatcher_with_send.send(self, data)

    def get(self, key, default=""):
        return self._get(self.session_id, key, default)

    def set(self, key, value):
        return self._set(self.session_id, key, value)

    @classmethod
    def get_session_id(cls):
        """\
        Obtain a fresh session identifier with an empty space
        """
        session_id = cls.sid
        cls.sessions[session_id] = {}
        cls.sid += 1
        return session_id

    @classmethod
    def has_session_id(cls, session_id):
        return session_id in cls.sessions

    @classmethod
    def _get(cls, session_id, key, default=""):
        return cls.sessions[session_id].get(key, default)

    @classmethod
    def _set(cls, session_id, key, value):
        cls.sessions[session_id][key] = value


class KVService(asyncore.dispatcher):
    """\
    Key-Value Service. Accept connections and delegate the work to the
    KVStore handler.
    """
    log = logging.getLogger("KVService")

    def __init__(self, addr, port, only_ipv4=False):
        """\
        `only_ipv4` will restrict the service to IPv4, otherwise both IPv6 and
        IPv4 are used.
        """
        asyncore.dispatcher.__init__(self)
        if only_ipv4:
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.create_socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((addr, port))
        self.listen(5)

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            self.log.debug("Incoming connection from %s" % repr(addr))
            KVStore(sock)


def main(argv):
    from optparse import OptionParser

    #logging.basicConfig(filename="/tmp/KVStore.log", level=logging.DEBUG)

    parser = OptionParser(description="Key Value store service for the Key "
                                      "Value Store plugin")
    parser.add_option("-p", "--port", dest="port", type=int, default=1234,
                      help="Listening port")
    parser.add_option("-H", "--host", dest="host", type=str, default="",
                      help="Hostname")
    parser.add_option("--only-ipv4", dest="ipv4", action="store_true",
                      default=False, help="Restrict to IPv4")

    (options, args) = parser.parse_args()

    kv = KVService(options.host, options.port, options.ipv4)
    try:
        logging.info("Listening on: %s:%d" % (options.host, options.port))
        logging.info("Relax")
        asyncore.loop()
        return 1
    except KeyboardInterrupt:
        logging.info("Closing")
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
