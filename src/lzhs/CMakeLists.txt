add_library(lzhs lzhs.c)

add_executable(lzhsenc lzhsenc.c)
target_link_libraries(lzhsenc lzhs)
