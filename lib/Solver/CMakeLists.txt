#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#
set(KLEE_SOLVER_SRCS CachingSolver.cpp
                     CexCachingSolver.cpp
                     ConstantDivision.cpp
                     FastCexSolver.cpp
                     IncompleteSolver.cpp
                     IndependentSolver.cpp
                     KQueryLoggingSolver.cpp
                     QueryLoggingSolver.cpp
                     SMTLIBLoggingSolver.cpp
                     Solver.cpp
                     SolverStats.cpp
)

if(ENABLE_SOLVER_Z3)
  list(APPEND KLEE_SOLVER_SRCS Z3ArrayBuilder.cpp
                               Z3Builder.cpp
                               Z3IteBuilder.cpp
                               Z3Solver.cpp)
endif()

klee_add_component(kleaverSolver ${KLEE_SOLVER_SRCS})

target_link_libraries(kleaverSolver PRIVATE ${KLEE_SOLVER_LIBRARIES})
