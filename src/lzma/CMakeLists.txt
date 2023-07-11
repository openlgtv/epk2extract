add_library(lzma LzFind.c LzmaDec.c LzmaEnc.c)
target_include_directories(lzma PUBLIC ${INC})