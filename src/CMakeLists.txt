set(INC ${CMAKE_SOURCE_DIR}/include)
include_directories(${INC} ${INC}/cramfs ${INC}/lzo ${INC}/squashfs ${INC}/lz4 ${INC}/jffs2 ${INC}/lzhs ${INC}/u-boot)
if(APPLE)
 include_directories(${INC}/osx)
endif(APPLE)

add_library(mfile mfile.c)
add_library(utils util.c util_crypto.c)

target_link_libraries(utils ${OPENSSL_LIBRARIES} mfile)

add_subdirectory(cramfs)
add_subdirectory(squashfs)
add_subdirectory(lz4)
add_subdirectory(jffs2)
add_subdirectory(lzhs)
add_subdirectory(stream)
add_subdirectory(tools)

add_executable(epk2extract
	main.c crc32.c epk1.c epk2.c mediatek_pkg.c
	mediatek.c symfile.c partinfo.c minigzip.c lzo-lg.c
)
target_link_libraries(epk2extract mfile utils cramfs squashfs lz4 jffs2 lzhs stream ${ZLIB_LIBRARIES} ${LZO_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${M_LIB})
