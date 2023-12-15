cmake_minimum_required(VERSION 3.21)

#
project(tls_certificate_verifier)

# use the c++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# any compiler flags that should be used
#
# 1. '03': enable alle optimizations
# 2. '-Wall': enable all warnings
set(CMAKE_CXX_FLAGS "-03 -Wall")

# specify the non-header source files that should be compiled
file(GLOB CPP_SOURCE
    "${PROJECT_SOURCE_DIR}/src/*.cpp"
    "${PROJECT_SOURCE_DIR}/src/*/*.cpp"
)


# where to find header files
include_directories($(PROJECT_SOURCE_DIR)/src)

# name of the executable to be created, and which source files to use
add_executable(main ${CPP_SOURCE})