add_library(lz4 lz4.c lz4hc.c lz4demo.c)
target_include_directories(lz4 PUBLIC ${INC}/lz4)