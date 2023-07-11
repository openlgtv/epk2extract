add_library(jffs2 crc32.cpp jffs2extract.cpp mini_inflate.cpp)
target_include_directories(jffs2 PUBLIC
	${INC}
	${LZO_INCLUDE_DIR}
	${INC}/jffs2
)
target_link_libraries(jffs2 util mfile lzma ${LZO_LIBRARIES})