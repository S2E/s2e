# Copyright (c) 2017 Cyberhaven
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

# _GNU_SOURCE: glibc only declares pthread_setname_np and friends with it (see utils/config-host.h).
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wno-initializer-overrides -fPIC -D_GNU_SOURCE")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror -fPIC -std=c++20")

add_library (
    utils

    coroutine/coroutine.c
    coroutine/coroutine-ucontext.c

    fsigc++/signals.cpp

    q/qobject/json-lexer.c
    q/qobject/json-parser-int.h
    q/qobject/json-parser.c
    q/qobject/json-streamer.c
    q/qobject/json-writer.c
    q/qobject/qbool.c
    q/qobject/qdict.c
    q/qobject/qjson.c
    q/qobject/qlist.c
    q/qobject/qlit.c
    q/qobject/qnull.c
    q/qobject/qnum.c
    q/qobject/qobject.c
    q/qobject/qstring.c
    q/qapi/qobject-output-visitor.c
    q/qapi/qobject-input-visitor.c
    q/qapi/qapi-forward-visitor.c
    q/qapi/qapi-visit-core.c
    q/qapi/qapi-util.c
    q/error.c
    q/unicode.c

    utils/bitmap.c
    utils/bufferiszero.c
    utils/cacheflush.c
    utils/cpuinfo-i386.c
    utils/cutils.c
    utils/event.c
    utils/hexdump.c
    utils/host-utils.c
    utils/interval-tree.c
    utils/memalign.c
    utils/notify.c
    utils/osdep.c
    utils/oslib-posix.c
    utils/qemu-thread-posix.c
    utils/qht.c
    utils/qtree.c
    utils/rcu.c
)

##########
# Tests  #
##########

add_executable(sigtest fsigc++/test.cpp)
target_link_libraries(sigtest utils)

foreach(test qdict qjson qlist qnull qnum qobject qstring)
    add_executable(check-${test} q/tests/check-${test}.c)
    target_link_libraries(check-${test} utils glib-2.0)
endforeach()
