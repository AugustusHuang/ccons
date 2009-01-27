cmake_minimum_required(VERSION 2.6)

set(LLVM_NO_RTTI 1)

find_program(LLVM_CONFIG_EXECUTABLE NAMES llvm-config PATHS /opt/local/bin)
if(NOT LLVM_CONFIG_EXECUTABLE)
  message(FATAL_ERROR "LLVM was not found!")
endif(NOT LLVM_CONFIG_EXECUTABLE)

exec_program(llvm-config ARGS --libs OUTPUT_VARIABLE LLVM_LIBS1)
set(LLVM_LIBS "-ldl ${LLVM_LIBS1}")
exec_program(llvm-config ARGS --ldflags OUTPUT_VARIABLE LLVM_LDFLAGS)
exec_program(llvm-config ARGS --includedir OUTPUT_VARIABLE LLVM_INCLUDE_DIR)
set(CLANG_LIBS "-lclangDriver -lclangAST -lclangLex -lclangCodeGen -lclangSema -lclangParse -lclangAST -lclangBasic")

Project(ccons)

add_executable(ccons ccons.cpp Console.cpp Parser.cpp)

include_directories(${LLVM_INCLUDE_DIR})
include_directories(../../include/)
include_directories(../clang/include/)

set_target_properties(ccons PROPERTIES LINK_FLAGS "${LLVM_LDFLAGS} -ldl")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS -fno-rtti")

set(LIBS ${LIBS} ${CLANG_LIBS} ${LLVM_LIBS})
set(LIBS ${LIBS} -ledit -lcurses)
target_link_libraries(ccons ${LIBS})
