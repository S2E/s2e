# Copyright (C) 2017, Cyberhaven
# All rights reserved.
#
# Licensed under the Cyberhaven Research License Agreement.

add_library(vmi STATIC DecreeFile.cpp
                       ElfDwarf.cpp
                       ExecutableFile.cpp
                       FileProvider.cpp
                       PEFile.cpp
                       Vmi.cpp
                       WindowsCrashDumpGenerator.cpp
                       WinKernDumpFile.cpp)

install(TARGETS vmi ARCHIVE DESTINATION lib)
