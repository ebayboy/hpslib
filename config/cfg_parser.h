
#ifndef __CFG_PARSER_H__
#define __CFG_PARSER_H__

#include "common.h"

typedef struct {
    char id[WAF_RULE_ID_LEN];
    char mz[WAF_RULE_MZ_LEN];
    char rx[WAF_RULE_RX_LEN];
} waf_rule_t;

typedef struct {
    waf_engine_e waf_engine;
    waf_action_e waf_action;
    char waf_id[WAF_ID_LEN];
  
    waf_rule_t rules[WAF_RULES_MAX];
} wafcfg_t;

int cfg_parser_parse(const char *filename, wafcfg_t *waf);

#endif


