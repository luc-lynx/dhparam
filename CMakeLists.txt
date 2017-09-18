cmake_minimum_required(VERSION 3.7)
project(dhparam)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

set(CMAKE_CXX_STANDARD 11)
set(SOURCE_FILES main.cpp)

add_executable(dhparam ${SOURCE_FILES})
target_link_libraries(dhparam crypto)