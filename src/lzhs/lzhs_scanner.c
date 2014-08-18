#include <stdio.h>
int main(int argc, char *argv[]){
	if(argc < 2){
		printf("Usage: %s [in]\n", argv[0]);
		return 1;
	}
	scan_lzhs(argv[1], 1);
	return 0;
}
