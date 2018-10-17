

#ifndef __COMMON_H__
#define __COMMON_H__

long fsize(FILE *fp);

#ifdef DEBUG 
#define PR(...) printf(__VA_ARGS__)
#else
#define PR(...)
#endif

#endif
