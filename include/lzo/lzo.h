#ifndef __LZO_LG_H
#define __LZO_LG_H
int check_lzo_header(const char *name);
int lzo_unpack(const char *in_name, const char *out_name);
#endif //__LZO_LG_H
