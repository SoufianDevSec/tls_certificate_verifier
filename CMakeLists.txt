cmake_minimum_required(VERSION 3.21)
project(tls_certificate_verifier)

# Use the C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# Any compiler flags that should be used
set(CMAKE_CXX_FLAGS "-O3 -Wall")
set(CMAKE_PREFIX_PATH "/usr/lib/x86_64-linux-gnu/cmake/Qt5")

# Find Qt5 and link libraries
find_package(Qt5 COMPONENTS Widgets Core Gui REQUIRED)

# Sodium
find_package(sodium REQUIRED)
set(CMAKE_PREFIX_PATH "/usr/lib/x86_64-linux-gnu/cmake/sodium")


# Specify the non-header source files that should be compiled
file(GLOB CPP_SOURCE "${PROJECT_SOURCE_DIR}/src/*.cpp" "${PROJECT_SOURCE_DIR}/src/*/*.cpp")

# Where to find header files
include_directories(${PROJECT_SOURCE_DIR}/src)

# Name of the executable to be created, and which source files to use
add_executable(main ${CPP_SOURCE})

# Link the Qt libraries
target_link_libraries(main Qt5::Widgets Qt5::Core Qt5::Gui)


target_link_libraries(main sodium)


# Find and link OpenSSL libraries
find_package(OpenSSL REQUIRED)
target_link_libraries(main OpenSSL::SSL OpenSSL::Crypto)
