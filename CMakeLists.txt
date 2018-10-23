cmake_minimum_required(VERSION 3.8)
project(forensics)

set(
  SRCS
  src/backtrace.h
  src/forensics.h
  src/forensics.cpp
  src/signals.h
)
if(APPLE)
  set(
    SRCS
    ${SRCS}
    src/backtrace_osx.cpp
    src/signals_osx.c
  )
endif()
if(WIN32)
  set(
    SRCS
    ${SRCS}
    src/backtrace_windows.cpp
    src/signals_windows.c
  )
endif()

# max out the warning settings for the compilers (why isn't there a generic way to do this?)
if(MSVC)
  string(REPLACE "/W3" "" CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
  string(REPLACE "/W3" "" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})
endif()

add_library(forensics STATIC ${SRCS})
target_compile_features(forensics PRIVATE cxx_std_11 cxx_thread_local)
target_compile_features(forensics PUBLIC cxx_variadic_macros)
target_include_directories(
  forensics
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
  $<INSTALL_INTERFACE:>
)
if(MSVC)
  target_compile_options(forensics PRIVATE /W4 /WX /wd4100)
elseif(APPLE)
  target_compile_options(forensics PRIVATE -Wall -Wextra -Wpedantic -Werror -Wno-unused-parameter)
endif()

set(
  TEST_SRCS
  spec/catch.hpp
  spec/main.cpp
  spec/forensics_spec.cpp
)

add_executable(test_runner ${TEST_SRCS})
target_compile_features(test_runner PRIVATE cxx_std_11)
target_link_libraries(test_runner forensics)
if(MSVC)
  target_compile_options(test_runner PRIVATE /W4 /WX /wd4100)
elseif(APPLE)
  target_compile_options(test_runner PRIVATE -Wall -Wextra -Wpedantic -Werror -Wno-unused-parameter)
endif()

enable_testing()
add_test(NAME spec COMMAND test_runner)
