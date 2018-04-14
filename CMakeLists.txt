cmake_minimum_required(VERSION 3.8)
project(forensics)

set(
  SRCS
  src/backtrace.h
  src/forensics.h
  src/forensics.cpp
)
if(APPLE)
  set(
    SRCS
    ${SRCS}
    src/backtrace_osx.cpp
  )
endif()
if(WIN32)
  set(
    SRCS
    ${SRCS}
    src/backtrace_windows.cpp
  )
endif()

# TODO: max out the warning settings for the compilers (why isn't there a generic way to do this?)
#if(MSVC)
#  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /WX")
#endif()

add_library(forensics STATIC ${SRCS})
target_compile_features(forensics PRIVATE cxx_std_11 cxx_thread_local)
target_compile_features(forensics PUBLIC cxx_variadic_macros)
target_include_directories(
  forensics
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
  $<INSTALL_INTERFACE:>
)

set(
  TEST_SRCS
  spec/catch.hpp
  spec/main.cpp
  spec/forensics_spec.cpp
)

add_executable(test_forensics ${TEST_SRCS})
target_compile_features(test_forensics PRIVATE cxx_std_11)
target_link_libraries(test_forensics forensics)

enable_testing()
add_test(NAME spec COMMAND test_forensics)
