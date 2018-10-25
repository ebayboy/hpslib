#ifndef __WAF_FILTER_H
#define __WAF_FILTER_H

#include <hs_common.h>
#include <hs_runtime.h>
#include <hs.h>


typedef struct {
    hs_database_t *db;
    hs_scratch_t *scratch;

    int *ids;
    char **rxs;
    int *flags;
    unsigned int idx_cursor; /* used for ids  & patterns & flags */
} filter_t;

filter_t * filter_new(void);
void filter_destroy(filter_t *p);
void filter_show(filter_t *filter);


#endif
