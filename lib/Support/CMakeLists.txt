#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#
klee_add_component(kleeSupport
	RNG.cpp
	Time.cpp
	Timer.cpp
)

target_link_libraries(kleeSupport PRIVATE ${ZLIB_LIBRARIES})
