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

} waf_match_t;

void waf_match_fini(waf_match_t *waf_match);
int waf_match_init(waf_match_t *waf_matcher, waf_config_t *cfg);
void waf_match_show(waf_match_t *waf_matcher);

#endif


