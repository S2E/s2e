add_executable(maze maze.c)
add_executable(quicksort quicksort.c)

# Disable optimizations to avoid interferring with vulnerabilities
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0")
add_executable(vulnerabilities vulnerabilities.c)
