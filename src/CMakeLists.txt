set(INC ${CMAKE_SOURCE_DIR}/include)


if(APPLE)
	include_directories(SYSTEM ${INC}/osx)
endif()

add_library(mfile mfile.c)
add_library(utils util.c util_crypto.c thpool.c)

target_include_directories(mfile PUBLIC ${INC})
target_include_directories(utils PUBLIC
	${INC}
	${INC}/u-boot
	${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(utils ${OPENSSL_LIBRARIES} mfile)

add_subdirectory(cramfs)
add_subdirectory(squashfs)
add_subdirectory(lz4)
add_subdirectory(lzma)
add_subdirectory(jffs2)
add_subdirectory(lzhs)
add_subdirectory(stream)
add_subdirectory(tools)

add_executable(epk2extract
	main.c crc32.c
	epk.c epk1.c epk2.c epk3.c
	mediatek_pkg.c
	mediatek.c philips.c symfile.c partinfo.c minigzip.c lzo-lg.c
	realtek.c
)

target_compile_definitions(epk2extract PRIVATE
	-D_GNU_SOURCE
	-D__USE_XOPEN_EXTENDED
	-DUSE_MMAP #for gzip
)

target_compile_options(epk2extract PRIVATE
	-Wunused
)

target_link_libraries(epk2extract
	mfile utils cramfs squashfs
	lz4 jffs2 lzhs stream
	${ZLIB_LIBRARIES} ${LZO_LIBRARIES}
	${CMAKE_THREAD_LIBS_INIT} ${M_LIB}
)
