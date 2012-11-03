project(epk2extract)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake-modules/")
find_package(OpenSSL REQUIRED)
find_package(LZO REQUIRED)
find_package(Threads REQUIRED)
find_library(M_LIB m REQUIRED)

include_directories(${LZO_INCLUDE_DIR})

add_subdirectory(src)
