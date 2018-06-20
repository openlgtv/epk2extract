add_executable(lzhsenc lzhsenc.c)
add_executable(lzhs_scanner lzhs_scanner.c)
add_executable(idb_extract idb_extract.c)
add_executable(jffs2extract jffs2extract.c)

target_link_libraries(idb_extract mfile utils)
target_link_libraries(lzhsenc lzhs)
target_link_libraries(lzhs_scanner utils lzhs)
target_link_libraries(jffs2extract jffs2 mfile utils)
