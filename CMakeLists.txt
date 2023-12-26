cmake_minimum_required(VERSION 3.21)

project(tls_certificate_verifier)

# Use the C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Any compiler flags that should be used
# 1. '-O3': enable all optimizations
# 2. '-Wall': enable all warnings
set(CMAKE_CXX_FLAGS "-O3 -Wall")

# Specify the non-header source files that should be compiled
file(GLOB CPP_SOURCE
    "${PROJECT_SOURCE_DIR}/src/*.cpp"
    "${PROJECT_SOURCE_DIR}/src/*/*.cpp"
)

# Where to find header files
include_directories(${PROJECT_SOURCE_DIR}/src)

# Name of the executable to be created, and which source files to use
add_executable(main ${CPP_SOURCE})

# Find and link OpenSSL libraries
find_package(OpenSSL REQUIRED)
target_link_libraries(main OpenSSL::SSL OpenSSL::Crypto)
