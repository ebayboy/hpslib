#ifndef _WAF_FILTER_H_
#define _WAF_FILTER_H_

#ifdef __cplusplus 
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>

void *waf_filter_new(void);
int waf_filter_addrule(void *h, uint32_t id,  char *pattern);
int waf_filter_compile(void *h);
int waf_filter_match(void *h, hs_scratch_t *scratch, char *buff, size_t len,
        uint32_t *matched_rule_id);
void waf_filter_destroy(void *h);
int waf_filter_serialize(void *h,  char **ptr, size_t *len);
int waf_filter_deserialize(void *h, char *ptr, size_t len);
int waf_filter_alloc_scratch(void *h, void **scratch);

#ifdef __cplusplus
}
#endif

#endif  /* _WAF_FILTER_H_ */

