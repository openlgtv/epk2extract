add_library(stream crc32.c tsfile.c)

target_include_directories(stream PUBLIC ${INC}/stream)
target_link_libraries(stream utils)