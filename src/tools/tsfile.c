#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "stream/tsfile.h"		/* STR and PIF */
#include "util.h"

int main(int argc, char *argv[]){
	char *tsfile = NULL;
	int ac = -1, vc = -1;

	int argi; // positional argument index
	for(int i=1; i<argc; i++){
		char *arg = argv[i];
		if(*arg != '-'){
			switch(argi++){
				case 0: tsfile = arg; break;
			}
		} else {
			if(!strcmp(arg, "-ac")){
				if(i + 1 < argc) ac = strtoul(argv[++i], NULL, 16);
			} else if(!strcmp(arg, "-vc")){
				if(i + 1 < argc) vc = strtoul(argv[++i], NULL, 16);
			}
		}
	}

	if(tsfile == NULL){
		fprintf(stderr,
			"Usage: %s [-ac type] [-vc type] <input file>\n"
			" -ac : specify audio codec (hex)\n"
			" -vc : specify video codec (hex)\n"
		, argv[0]);
		return 1;
	}

	// disable output buffering
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	if(!isSTRfile(tsfile)){
		fprintf(stderr, "%s is not a valid STR file\n", tsfile);
		return 1;
	}

	struct tsfile_options opts = {
		.video_stream_type = vc,
		.audio_stream_type = ac,
		.append = 0
	};

	convertSTR2TS(tsfile, &opts);
	return 0;
}