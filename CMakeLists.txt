set(CMAKE_LEGACY_CYGWIN_WIN32 0)

project(epk2extract)
cmake_minimum_required(VERSION 2.8)

if( NOT CMAKE_BUILD_TYPE )
	set(CMAKE_BUILD_TYPE Debug)
endif()

set(CMAKE_CXX_FLAGS_TEST "-Ofast")
set(CMAKE_C_FLAGS_TEST "-Ofast -funroll-loops -fprefetch-loop-arrays -march=native")

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)

add_definitions(-D_GNU_SOURCE -D__USE_XOPEN_EXTENDED)
add_definitions(-DUSE_MMAP) #for gzip
add_definitions(-DGZIP_SUPPORT -DLZO_SUPPORT -DCOMP_DEFAULT=\"gzip\" -DXATTR_SUPPORT -DXATTR_DEFAULT) #for squashfs
add_definitions(-Wunused)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake-modules/")
find_package(OpenSSL REQUIRED)
find_package(LZO REQUIRED)
find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
find_library(M_LIB m REQUIRED)

include_directories(${LZO_INCLUDE_DIR})

add_subdirectory(src)
