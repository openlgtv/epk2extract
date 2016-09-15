#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>

#include "main.h" //for handle_file
#include "mfile.h"
#include "hisense.h"
#include "util.h"

MFILE *is_hisense(const char *pkgfile){
	MFILE *mf = mopen(pkgfile, O_RDONLY);
	if(!mf){
		err_exit("Cannot open file %s\n", pkgfile);
	}
	
	uint8_t *data = mdata(mf, uint8_t);
	data = &data[UPG_HEADER_SIZE];

	/* First pak doesn't have OTA ID fields */
	struct hipkg *cfig = (struct hipkg *)data;
	if(
		(!strcmp(cfig->pakName, "cfig")) &&
		(!strncmp(cfig->data, "START", 5))
	){
		/* Checking for END may be desirable */
		return mf;
	}
	mclose(mf);
	return NULL;
}

void extract_hisense(MFILE *mf, struct config_opts_t *config_opts){
	uint8_t *data = mdata(mf, uint8_t) + UPG_HEADER_SIZE;
	
	char *file_name = my_basename(mf->path);
	char *file_base = remove_ext(file_name);

	off_t i = UPG_HEADER_SIZE;
	
	int pakNo;
	for(pakNo=0; i < msize(mf); pakNo++){
		struct hipkg *pak = (struct hipkg *)data;
		/* End of package */
		if(pak->size == 0){
			break;
		}
		printf("PAK #%u (name='%s', offset='0x%lx', size='%u bytes'",
			pakNo + 1, pak->pakName, moff(mf, data), pak->size
		);

		data += sizeof(*pak);

		uint8_t *pkgData = pak->data;

		char *dest_path;
		struct hipkg_plat *ext = (struct hipkg_plat *)pkgData;
		if(!strncmp(ext->platform, HISENSE_MTK_MAGIC, strlen(HISENSE_MTK_MAGIC))){
			printf(", platform='%s', otaid='%s')\n", ext->platform, ext->otaID);
			if(pakNo == 1){
				sprintf(config_opts->dest_dir, "%s/%s", config_opts->dest_dir, ext->otaID);
				createFolder(config_opts->dest_dir);
			}
			pkgData += sizeof(*ext) + ext->otaID_len;
		} else {
			printf(")\n");
		}

		struct hipkg_pad *pad = (struct hipkg_pad *)pkgData;
		if(!strncmp(pad->magic, HISENSE_PAD_MAGIC, strlen(HISENSE_PAD_MAGIC))){
			pkgData += sizeof(*pad);
		}

		asprintf(&dest_path, "%s/%s.pak", config_opts->dest_dir, pak->pakName);

		MFILE *out = mfopen(dest_path, "w+");
		if(!out){
			err_exit("Cannot open %s for writing\n", dest_path);
		}

		printf("Saving partition (%s) to file %s\n\n", pak->pakName, dest_path);

		mfile_map(out, pak->size);
		memcpy(
			mdata(out, void),
			pkgData,
			pak->size
		);
		mclose(out);
		handle_file(dest_path, config_opts);
		free(dest_path);

		data += pak->size;
	}

	free(file_name);
	free(file_base);
}