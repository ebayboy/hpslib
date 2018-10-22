
#ifndef __CFG_PARSER_H__
#define __CFG_PARSER_H__

#define WAF_ID_MAX       64

#define WAF_RULES_MAX       1024
#define WAF_RULE_ID_MAX     64
#define WAF_RULE_MZ_MAX     1024
#define WAF_RULE_RX_MAX     4096

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

typedef struct _waf_rules_t {
    char id[WAF_RULE_ID_MAX];
    char mz[WAF_RULE_MZ_MAX];
    char rx[WAF_RULE_RX_MAX];
} waf_rule_t;

typedef struct _cfgwaf_s {
    waf_engine_e waf_engine;
    waf_action_e waf_action;
    char waf_id[WAF_ID_MAX];
   
    waf_rule_t rules[WAF_RULES_MAX];
} waf_t;

int cfg_parser_parse(const char *filename);
int cfg_parser_parse2(const char *filename);

#endif


