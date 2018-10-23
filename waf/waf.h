#ifndef __WAF_H
#define __WAF_H

#include <stdio.h>

#include "common.h"
#include "match.h"
#include "filter.h"

typedef struct {
    FILE *log_fp;
    waf_match_t waf_matcher;
} waf_t;

int waf_init(const char *logfile);

int waf_fini(void);

#endif

