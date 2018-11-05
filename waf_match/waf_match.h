#ifndef __WAF_MATCH_H
#define __WAF_MATCH_H

#include "common.h"
#include "filter.h"
#include "waf_config.h"

typedef struct {
    waf_engine_e waf_engine;
    waf_action_e waf_action;
    char waf_id[WAF_ID_LEN];

    match_t *matchers[WAF_MZ_MAX]; /* WAF_MZ_MAX */
    int matcher_cursor;
} waf_match_t;

int waf_match_init(waf_match_t *waf_matcher, waf_config_t *cfg);

void waf_match_fini(waf_match_t *waf_match);

void waf_match_show(waf_match_t *waf_matcher);

int waf_match_match(waf_match_t *waf_matcher, 
        const unsigned char *mz, 
        size_t mzlen,
        unsigned int mz_hash, 
        const unsigned char *buff, 
        size_t blen, 
        int *matched_rule_id);
 
#endif


