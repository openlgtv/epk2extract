add_executable(lzhsenc lzhsenc.c)
add_executable(lzhs_scanner lzhs_scanner.c)
target_link_libraries(lzhsenc lzhs)
target_link_libraries(lzhs_scanner utils lzhs)
