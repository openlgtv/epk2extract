#include <stdio.h>
int main(int argc, char *argv[]) {
	if (argc < 3) {
		printf("Usage: \n");
		printf("'%s [in] 0' scan\n", argv[0]);
		printf("'%s [in] 1' scan and extract\n", argv[0]);
		return 1;
	}
	scan_lzhs(argv[1], atoi(argv[2]));
	return 0;
}
