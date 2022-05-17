add_executable(maze maze.c)
target_link_options(maze PUBLIC ${COMPAT_LD_FLAGS})


add_executable(quicksort quicksort.c)
target_link_options(quicksort PUBLIC ${COMPAT_LD_FLAGS})

# Disable optimizations to avoid interferring with vulnerabilities
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0")
add_executable(vulnerabilities vulnerabilities.c)
target_link_options(vulnerabilities PUBLIC ${COMPAT_LD_FLAGS})

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    add_dependencies(maze glibc-compat-main)
    add_dependencies(quicksort glibc-compat-main)
    add_dependencies(vulnerabilities glibc-compat-main)
endif()