
#ifndef __CFG_PARSER_H__
#define __CFG_PARSER_H__

#include "common.h"

typedef enum {
    WAF_ENGINE_OFF = 0, 
    WAF_ENGINE_ON = 1
} waf_engine_e;

typedef enum {
    WAF_ACT_NONE = 0,
    WAF_ACT_LOG,
    WAF_ACT_PASS,
    WAF_ACT_BLOCK,
    WAF_ACT_MAX
} waf_action_e;

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


