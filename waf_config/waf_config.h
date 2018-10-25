
#ifndef __CFG_PARSER_H__
#define __CFG_PARSER_H__

#include "common.h"

typedef struct {
    int id;
    char mz[WAF_RULE_MZS_LEN];
    char rx[WAF_RULE_RX_LEN];
} waf_rule_t;

typedef struct {
    waf_engine_e waf_engine;
    waf_action_e waf_action;
    char waf_id[WAF_ID_LEN];
  
    waf_rule_t rules[WAF_RULES_MAX];
    int idx_cursor;
} waf_config_t;

int waf_config_init(const char *filename, waf_config_t *waf);
void waf_config_show(waf_config_t *cfg);

#endif


