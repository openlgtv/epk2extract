add_library(squashfs compressor.c gzip_wrapper.c lzo_wrapper.c swap.c read_xattrs.c unsquash-1.c unsquash-2.c unsquash-3.c unsquash-4.c unsquashfs.c unsquashfs_info.c unsquashfs_xattr.c)
target_include_directories(squashfs PUBLIC
	${INC}/squashfs
	${LZO_INCLUDE_DIR}
)
target_compile_definitions(squashfs PRIVATE
	-DGZIP_SUPPORT
	-DLZO_SUPPORT
	-DCOMP_DEFAULT=\"gzip\"
	-DXATTR_SUPPORT
	-DXATTR_DEFAULT
)