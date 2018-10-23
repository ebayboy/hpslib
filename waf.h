#ifndef __WAF_H
#define __WAF_H

#include <stdio.h>

typedef struct {
    FILE *log_fp;
} waf_t;

int waf_init(const char *logfile);

#endif

