#ifndef __MATCH_H
#define __MATCH_H

#include "common.h"
#include "filter.h"

typedef struct {
    filter_t *filter;                
    char mz[WAF_RULE_MZ_LEN];  
} match_t;

match_t * match_new();
void match_destroy(match_t *matcher);

#endif


