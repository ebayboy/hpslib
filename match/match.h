#ifndef __MATCH_H
#define __MATCH_H

#include "common.h"
#include "filter.h"

typedef struct {
    filter_t *filter;                
    char mz[WAF_RULE_MZ_LEN];  
    unsigned int mz_hash;
} match_t;

match_t * match_new();
void match_destroy(match_t *matcher);
void match_show(match_t *matcher);
int match_build(match_t *matcher);
int match_match(match_t *matcher, const char *buff, size_t len, int *matched_rule_id);

#endif


