#ifndef __MATCH_H
#define __MATCH_H

#include "common.h"
#include "filter.h"

typedef struct {
    filter_t *filter;                
    char mz[WAF_RULE_MZ_LEN];  
} match_t;

#endif


