add_library(cramfs cramfsswap.c uncramfs.c)
target_include_directories(cramfs PUBLIC
	${INC}
	${INC}/cramfs
)