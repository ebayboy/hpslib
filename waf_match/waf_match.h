#ifndef __WAF_MATCH_H
#define __WAF_MATCH_H

#include "common.h"
#include "filter.h"

typedef struct {
    waf_engine_e waf_engine;
    waf_action_e waf_action;
    char waf_id[WAF_ID_LEN];

    match_t matchers[WAF_MZ_MAX];

} waf_match_t;

#endif


