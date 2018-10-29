#ifndef __WAF_H
#define __WAF_H

#include <stdio.h>

int waf_init(const char *log_fname, const char *cfg_fname);

void waf_fini(void);

void waf_show();

int waf_match(const unsigned char *mz,
        const unsigned char *buff,
        size_t blen, 
        int *matched_rule_id);

#endif

