#ifndef __WAF_H
#define __WAF_H

#include <stdio.h>

#include "common.h"
#include "match.h"
#include "waf_match.h"
#include "filter.h"
#include "waf_config.h"

typedef struct {
    FILE *log_fp;
    waf_config_t waf_config;
    waf_match_t waf_matcher;
} waf_t;

int waf_init(const char *logfile, const char *config);

int waf_fini(void);

#endif

