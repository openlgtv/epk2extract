#ifndef __UTIL_H
#define __UTIL_H
char *my_basename(const char *path);
char *my_dirname(const char *path);
int err_ret(const char *format, ...);
void rmrf(char *path);
void unnfsb(char *filename, char *extractedFile);
#endif
