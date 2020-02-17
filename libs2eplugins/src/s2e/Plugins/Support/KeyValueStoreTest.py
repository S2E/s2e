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


import re
import unittest

from KeyValueStore import KVStore


class MockSocket(object):
    """\
    Mock for socket.socket
    """

    attr = {
        "closed": False,
        "input": "",
        "output": ""
    }

    def getpeername(self):
        return "mock"

    def fileno(self):
        return None

    def setblocking(self, blocking):
        pass

    def recv(self, len):
        recv = self.attr["input"]
        self.attr["input"] = ""
        return recv

    def close(self):
        self.attr["closed"] = True

    def send(self, data):
        self.attr["output"] += data
        return len(data)

    def flush(self):
        self.attr["output"] = ""

    def __getattr__(self, name):
        return self.attr.get(name, None)

    def __setattr__(self, name, value):
        self.attr[name] = value


class KeyValueStoreTest(unittest.TestCase):
    """\
    Testing nominal usage of the KVStore.
    """

    def setUp(self):
        self.sock = MockSocket()
        self.kv = KVStore(self.sock)

    def tearDown(self):
        self.sock.flush()

    def test_get_session_id(self):
        session_id = KVStore.sid
        self.sock.input = "get-session-id"
        self.kv.handle_read()
        self.assertEquals(str(session_id), self.sock.output.strip())

    def test_get_session_id_twice(self):
        self.sock.input = "get-session-id"
        self.kv.handle_read()
        session_id = self.sock.output
        self.sock.flush()
        self.sock.input = "get-session-id"
        self.kv.handle_read()
        self.assertEquals(session_id, self.sock.output)

    def test_set_session_id(self):
        self.sock.input = "set-session-id 0"
        self.kv.handle_read()
        self.assertEquals("OK", self.sock.output.strip())

    def test_set_unknown_session_id(self):
        self.sock.input = "set-session-id 0xDEADBEEF"
        self.kv.handle_read()
        self.assertNotEquals("OK", self.sock.output.strip())

    def test_000_set_value(self):
        self.sock.input = "get-session-id"
        self.kv.handle_read()
        self.sock.flush()
        self.sock.input = "set-value spam=eggs"
        self.kv.handle_read()
        self.assertEquals("OK", self.sock.output.strip())

    def test_001_get_value(self):
        self.sock.input = "set-session-id %d" % (KVStore.sid - 1)
        self.kv.handle_read()
        self.sock.flush()
        self.sock.input = "get-value spam"
        self.kv.handle_read()
        self.assertEquals("eggs", self.sock.output.strip())

    def test_get_default_value(self):
        self.sock.input = "get-session-id"
        self.kv.handle_read()
        self.sock.flush()
        self.sock.input = "get-value eggs"
        self.kv.handle_read()
        self.assertEquals("", self.sock.output.strip())

    def test_get_value_no_session_id(self):
        self.sock.input = "get-value eggs"
        self.kv.handle_read()
        self.assertTrue(self.sock.output.startswith("ERROR"))

    def test_set_value_malformed(self):
        self.sock.input = "get-session-id"
        self.kv.handle_read()
        self.sock.flush()
        self.sock.input = "set-value spam eggs"
        self.kv.handle_read()
        self.assertTrue(self.sock.output.startswith("ERROR"))

    def test_unknown_command(self):
        self.sock.input = "get-session-id"
        self.kv.handle_read()
        self.sock.flush()
        self.sock.input = "set a=12"
        self.kv.handle_read()
        self.assertTrue(self.sock.output.startswith("ERROR"))

    def test_bulk(self):
        self.sock.input = """
            get-session-id
            set-value spam=eggs
            set-value herp=derp
            set-value a=b
            get-value spam"""
        self.kv.handle_read()
        self.assertTrue(self.sock.output.strip().endswith("eggs"))

    def test_overriding_value(self):
        self.sock.input = """
            get-session-id
            set-value spam=eggs
            set-value spam=foobar
            set-value spam=fizzbuzz
            get-value spam"""
        self.kv.handle_read()
        self.assertTrue(self.sock.output.strip().endswith("fizzbuzz"))

    def test_quit(self):
        self.sock.input = "quit"
        self.kv.handle_read()
        self.assertTrue(self.sock.closed)

    def test_connection_closed(self):
        self.sock.input = None
        self.kv.handle_read()
        self.assertTrue(self.sock.closed)


if __name__ == "__main__":
    unittest.main()
