set(INC ${CMAKE_SOURCE_DIR}/include)
include_directories(${INC} ${INC}/cramfs ${INC}/lzo ${INC}/squashfs ${INC}/lz4 ${INC}/u-boot)

add_subdirectory(cramfs)
add_subdirectory(squashfs)
add_subdirectory(lz4)

add_executable(epk2extract main.c crc32.c epk.c epk1.c epk2.c log.c symfile.c util.c lzo-lg.c)

target_link_libraries(epk2extract cramfs squashfs lz4 ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARIES} ${LZO_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${M_LIB})
