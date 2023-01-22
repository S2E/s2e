# Copyright 2016 - Cyberhaven
# This work is licensed under the terms of the GNU LGPL, version 2.1 or later.

add_library (
    q 
    qobject/json-lexer.c
    qobject/json-parser-int.h
    qobject/json-parser.c
    qobject/json-streamer.c
    qobject/json-writer.c
    qobject/qbool.c
    qobject/qdict.c
    qobject/qjson.c
    qobject/qlist.c
    qobject/qlit.c
    qobject/qnull.c
    qobject/qnum.c
    qobject/qobject.c
    qobject/qstring.c
    qapi/qobject-output-visitor.c
    qapi/qobject-input-visitor.c
    qapi/qapi-forward-visitor.c
    qapi/qapi-visit-core.c
    qapi/qapi-util.c
    error.c
    unicode.c
    cutils.c
)

add_executable (check-qdict tests/check-qdict.c)
target_link_libraries(check-qdict q glib-2.0)

add_executable (check-qjson tests/check-qjson.c)
target_link_libraries(check-qjson q glib-2.0)

add_executable (check-qlist tests/check-qlist.c)
target_link_libraries(check-qlist q glib-2.0)

add_executable (check-qnull tests/check-qnull.c)
target_link_libraries(check-qnull q glib-2.0)

add_executable (check-qnum tests/check-qnum.c)
target_link_libraries(check-qnum q glib-2.0)

add_executable (check-qobject tests/check-qobject.c)
target_link_libraries(check-qobject q glib-2.0)

add_executable (check-qstring tests/check-qstring.c)
target_link_libraries(check-qstring q glib-2.0)


set(CMAKE_C_FLAGS "-Wall -Werror -Wno-initializer-overrides -fPIC")
