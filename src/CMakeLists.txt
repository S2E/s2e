# Copyright 2016 - Cyberhaven
# This work is licensed under the terms of the GNU LGPL, version 2.1 or later.

add_library(coroutine coroutine.c coroutine-ucontext.c)

set(CMAKE_C_FLAGS "-Wall -Werror -fPIC")
