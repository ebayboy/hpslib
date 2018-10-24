#ifndef __WAF_H
#define __WAF_H

#include <stdio.h>

#include "common.h"
#include "match.h"
#include "waf_match.h"
#include "filter.h"
#include "waf_config.h"

int waf_init(const char *log_fname, const char *cfg_fname);
void waf_fini(void);

#endif

