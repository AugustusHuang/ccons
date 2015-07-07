cmake_minimum_required(VERSION 2.6)

# llvm doesn't support in-tree build so I suppose we have ccons in
# xx/llvm/tools/ccons/ but llvm executables in xx/build/bin/.
# Find llvm-config in "../../../Release+Asserts/bin".
find_program(LLVM_CONFIG_EXECUTABLE NAMES llvm-config PATHS "../../../Release+Asserts/bin" NO_DEFAULT_PATH)
# Find llvm-config in "../../../Debug+Asserts/bin".
find_program(LLVM_CONFIG_EXECUTABLE NAMES llvm-config PATHS "../../../Debug+Asserts/bin" NO_DEFAULT_PATH)
# Find llvm-config in "../../../build/bin".
find_program(LLVM_CONFIG_EXECUTABLE NAMES llvm-config PATHS "../../../build/bin" NO_DEFAULT_PATH)
find_program(LLVM_CONFIG_EXECUTABLE llvm-config)

if(NOT LLVM_CONFIG_EXECUTABLE)
  message(FATAL_ERROR "LLVM was not found!")
endif(NOT LLVM_CONFIG_EXECUTABLE)

# LLVM_LIBS = ./llvm-config --libs engine target...
exec_program(${LLVM_CONFIG_EXECUTABLE} ARGS --libs engine target linker bitreader bitwriter codegen mc mcdisassembler instrumentation x86 OUTPUT_VARIABLE LLVM_LIBS)
# LLVM_SYSTEM_LIBS = ./llvm-config --system-libs engine target...
exec_program(${LLVM_CONFIG_EXECUTABLE} ARGS --system-libs engine target linker bitreader bitwriter codegen mc mcdisassembler instrumentation x86 OUTPUT_VARIABLE LLVM_SYSTEM_LIBS)
# LLVM_LIBDIR = ./llvm-config --libdir
exec_program(${LLVM_CONFIG_EXECUTABLE} ARGS --libdir OUTPUT_VARIABLE LLVM_LIBDIR)
# LLVM_LDFLAGS = ./llvm-config --ldflags
exec_program(${LLVM_CONFIG_EXECUTABLE} ARGS --ldflags OUTPUT_VARIABLE LLVM_LDFLAGS)
# LLMV_INCLUDE_DIR = ./llvm-config --includedir
exec_program(${LLVM_CONFIG_EXECUTABLE} ARGS --includedir OUTPUT_VARIABLE LLVM_INCLUDE_DIR)
# LLVM_C_FLAGS = ./llvm-config --cflags
exec_program(${LLVM_CONFIG_EXECUTABLE} ARGS --cflags OUTPUT_VARIABLE LLVM_C_FLAGS)
# LLVM_CXX_FLAGS = ./llvm-config --cxxflags
exec_program(${LLVM_CONFIG_EXECUTABLE} ARGS --cxxflags OUTPUT_VARIABLE LLVM_CXX_FLAGS)
set(CLANG_LIBS "-lclangFrontendTool -lclangFrontend -lclangDriver -lclangSerialization -lclangCodeGen -lclangParse -lclangSema -lclangStaticAnalyzerFrontend -lclangStaticAnalyzerCheckers -lclangStaticAnalyzerCore -lclangAnalysis -lclangARCMigrate -lclangRewriteFrontend -lclangEdit -lclangAST -lclangLex -lclangBasic")

Project(ccons)

set(CCONS_SRCS ccons.cpp Diagnostics.cpp ClangUtils.cpp Console.cpp Parser.cpp SrcGen.cpp StringUtils.cpp EditLineReader.cpp InternalCommands.cpp LineReader.cpp RemoteConsole.cpp Visitors.cpp complete.c popen2.c)
if(CMAKE_GENERATOR STREQUAL "Xcode")
    set(CCONS_HDRS ClangUtils.h InternalCommands.h SrcGen.h popen2.h Console.h LineReader.h StringUtils.h Diagnostics.h Parser.h Visitors.h EditLineReader.h RemoteConsole.h complete.h)
endif()

add_executable(ccons ${CCONS_SRCS} ${CCONS_HDRS})

include_directories(${LLVM_INCLUDE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/../clang/include/)
include_directories(${CMAKE_SOURCE_DIR}/../../../build/include/)
include_directories(${CMAKE_SOURCE_DIR}/../../../build/tools/clang/include/)

set_target_properties(ccons PROPERTIES LINK_FLAGS "${LLVM_LDFLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -O0 -g")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${LLVM_CXX_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LLVM_C_FLAGS}")

set(LIBS ${LIBS} "-L${LLVM_LIBDIR}")
set(LIBS ${LIBS} ${CLANG_LIBS})
set(LIBS ${LIBS} ${LLVM_LIBS})
set(LIBS ${LIBS} ${CMAKE_DL_LIBS})
set(LIBS ${LIBS} -ledit -lcurses)
set(SYSTEM_LIBS ${SYSTEM_LIBS} ${LLVM_SYSTEM_LIBS})
target_link_libraries(ccons ${LIBS} ${SYSTEM_LIBS})

install(FILES man/ccons.1 DESTINATION share/man/man1)
install(PROGRAMS ccons DESTINATION bin)
