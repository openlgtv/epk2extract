/*
 * Copyright (c) 2011 Roman Tokarev <roman.s.tokarev@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of any co-contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY CONTRIBUTORS ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <symfile.h>

#include <log.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#define MAGIC 0xB12791EE

struct symfile_header {
	uint32_t magic;
	uint32_t unknown;
	uint32_t size;
	uint32_t n_symbols;
	uint32_t tail_size;
}__attribute__((packed));

struct sym_table sym_table = { .n_symbols = 0, .sym_entry = NULL, .hash = NULL,
		.n_dwarf_lst = 0, .dwarf_lst = NULL, .dwarf_data = NULL, .sym_name =
				NULL };

int symfile_load(const char *fname) {
	int fd = -1;
	struct stat st_buf;
	void *p;
	struct symfile_header *header;
	uint32_t *has_hash, *has_dwarf;
	uint32_t dwarf_data_size = 0;

	fd = open(fname, O_RDONLY);
	if (fd == -1) {
		say_error("can't open `%s': %m", fname);

		return -1;
	}

	if (fstat(fd, &st_buf) != 0) {
		say_error("fstat for `%s' is failed: %m", fname);

		return -1;
	}

	p = mmap(NULL, st_buf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	header = p;
	p += sizeof(*header);
	if (header == NULL) {
		say_error("can't mmap `%s': %m", fname);

		return -1;
	}

	if (header->magic != MAGIC) {
		say_error("bad magic 0x%x from `%s'", header->magic, fname);

		return -1;
	}

	if ((header->size + sizeof(*header)) != (uint32_t) st_buf.st_size) {
		say_error("bad file `%s' size: %su, expected size: %lu", fname,
				st_buf.st_size, header->size + sizeof(*header));

		return -1;
	}

	if ((header->tail_size + sizeof(struct sym_entry) * header->n_symbols)
			!= header->size) {
		say_error("file `%s' is broken", fname);

		return -1;
	}

	sym_table.n_symbols = header->n_symbols;
	sym_table.sym_entry = p;
	p += sizeof(sym_table.sym_entry[0]) * sym_table.n_symbols;

	has_hash = p;
	p += sizeof(*has_hash);
	if (*has_hash != 2 && *has_hash != 0) {
		say_error("unsupported file `%s' format", fname);

		return -1;
	}

	if (*has_hash == 2) {
		sym_table.hash = p;
		p += sizeof(sym_table.hash[0]) * ((sym_table.n_symbols + 1) & (~0 - 1));
	}

	has_dwarf = p;
	p += sizeof(*has_dwarf);
	if (*has_dwarf > 1) {
		say_error("unsupported file `%s' format", fname);

		return -1;
	}

	if (*has_dwarf == 1) {
		sym_table.n_dwarf_lst = *(uint32_t *) p;
		p += sizeof(sym_table.n_dwarf_lst);
		dwarf_data_size = *(uint32_t *) p;
		p += sizeof(dwarf_data_size);
		sym_table.dwarf_lst = p;
		p += sizeof(sym_table.dwarf_lst[0]) * sym_table.n_dwarf_lst;
		sym_table.dwarf_data = p;
		p += dwarf_data_size;
	}

	sym_table.sym_name = p;

	say_info("`%s' has been successfully loaded", fname);

	return 0;
}

uint32_t symfile_addr_by_name(const char *name) {
	unsigned i = 0;
	for (i = 0; i < sym_table.n_symbols; ++i) {
		char *sym_name = sym_table.sym_name
				+ sym_table.sym_entry[i].sym_name_off;

		if (strcmp(sym_name, name) == 0)
			return sym_table.sym_entry[i].addr;
	}

	return 0;
}

uint32_t symfile_n_symbols() {
	return sym_table.n_symbols;
}

void symfile_write_idc(const char *fname) {

	FILE *outfile = fopen(fname, "w");

	fprintf(outfile, "%s\n\n", "#include <idc.idc>");
	fprintf(outfile, "%s\n", "static main() {");

	unsigned i = 0;
	for (i = 0; i < sym_table.n_symbols; ++i) {
			char *sym_name = sym_table.sym_name
					+ sym_table.sym_entry[i].sym_name_off;

			uint32_t addr = sym_table.sym_entry[i].addr;
			uint32_t end = sym_table.sym_entry[i].end;

			//printf("%s: %x...%x\n", sym_name, addr, end);

			fprintf(outfile, "MakeNameEx( 0x%x, \"%s\", SN_NOWARN | SN_CHECK);\n", addr, sym_name);

			fprintf(outfile, "if(SegName(0x%x)==\".text\") {\n", addr);
			fprintf(outfile, "   MakeCode(0x%x);\n", addr);
			fprintf(outfile, "   MakeFunction(0x%x, 0x%x);\n", addr, end);
			fprintf(outfile, "};\n", addr);

	}

	fprintf(outfile, "%s\n", "}");

	fclose(outfile);

	//printf("n_dwarf_lst: %d\n", sym_table.n_dwarf_lst);
	//printf("dwarf_lst.d1: %d\n", sym_table.dwarf_lst->d1);
	//printf("dwarf_lst.d2: %d\n", sym_table.dwarf_lst->d2);

	//hexdump(sym_table.dwarf_data, 15000);

}


const char *symfile_name_by_addr(uint32_t addr) {
	int i = 0;
	for (i = sym_table.n_symbols - 1; i >= 0; --i) {
		if (sym_table.sym_entry[i].addr <= addr && sym_table.sym_entry[i].end
				> addr)
			return sym_table.sym_name + sym_table.sym_entry[i].sym_name_off;
	}

	return NULL;
}
