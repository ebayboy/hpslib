#ifndef __WAF_FILTER_H
#define __WAF_FILTER_H

#include <hs_common.h>
#include <hs_runtime.h>
#include <hs.h>

typedef struct {
    hs_database_t *db;
    hs_scratch_t *scratch;

    int  *ids;
    char **patterns;
    int *flags;
    unsigned int patterns_size;
} filter_t;

#endif
