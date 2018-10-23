#ifndef __WAF_H
#define __WAF_H

#include <stdio.h>

#include "common.h"
#include "match.h"
#include "filter.h"

typedef struct {
    waf_engine_e waf_engine;
    waf_action_e waf_action;
    char waf_id[WAF_ID_LEN];

    match_t matchers[WAF_MZ_MAX];

} waf_match_t;

typedef struct {
    FILE *log_fp;
} waf_t;

int waf_init(const char *logfile);

int waf_fini(void);

#endif

