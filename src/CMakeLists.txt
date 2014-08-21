set(INC ${CMAKE_SOURCE_DIR}/include)
include_directories(${INC} ${INC}/cramfs ${INC}/lzo ${INC}/squashfs ${INC}/lz4 ${INC}/jffs2 ${INC}/lzhs ${INC}/u-boot)

add_library(utils util.c)
target_link_libraries(utils ${OPENSSL_LIBRARIES})

add_subdirectory(cramfs)
add_subdirectory(squashfs)
add_subdirectory(lz4)
add_subdirectory(jffs2)
add_subdirectory(lzhs)
add_subdirectory(stream)
add_subdirectory(tools)

add_executable(epk2extract main.c crc32.c epk1.c epk2.c log.c symfile.c partinfo.c minigzip.c lzo-lg.c)
target_link_libraries(epk2extract utils cramfs squashfs lz4 jffs2 lzhs stream ${ZLIB_LIBRARIES} ${LZO_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${M_LIB})
