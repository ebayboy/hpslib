
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include <hs_common.h>
#include <hs_runtime.h>
#include <hs.h>

#include "waf.h"
#include "log.h"
#include "common.h"
#include "filter.h"

static int filter_compile_db(filter_t *f) 
{
    hs_compile_error_t *compileErr = NULL;
    hs_error_t err;

    err = hs_compile_multi((const char *const *)f->rxs, f->flags, f->ids,
            f->idx_cursor, HS_MODE_BLOCK, NULL, &f->db, &compileErr);

    if (err != HS_SUCCESS) {
        if (compileErr->expression < 0) {
            log_error("%s", compileErr->message);
        } else {
            log_error("hs_compile_multi '%d' failed with error '%s'",
                    f->ids[compileErr->expression], compileErr->message);
        }
        hs_free_compile_error(compileErr);

        return -1;
    }

    return 0;
}

static int filter_alloc_scratch(filter_t *filter)
{
    if (filter == NULL || filter->db == NULL) {
        log_error("filter or filter->db is NULL");
        return -1;
    }

    hs_error_t err = hs_alloc_scratch(filter->db, &filter->scratch);
    if (err != HS_SUCCESS) {
        log_error("hs_alloc_scratch");
        return -1;
    }

    return 0;
}

int filter_build(filter_t *filter)
{
    if (filter_compile_db(filter) == -1) {
        log_error("filter_compile_db");
        return -1;
    }

    if (filter_alloc_scratch(filter) == -1) {
        log_error("filter_alloc_scratch");
        return -1;
    }

    return 0;
}


filter_t * filter_new(void)
{
    filter_t *p = malloc(sizeof(filter_t));
    memset(p, 0, sizeof(filter_t));

    p->ids = malloc(WAF_RULES_MAX*sizeof(int));
    memset(p->ids, 0, WAF_RULES_MAX*sizeof(int));

    p->flags = malloc(WAF_RULES_MAX*sizeof(int));
    memset(p->flags, 0, WAF_RULES_MAX*sizeof(int));

    p->rxs = malloc(WAF_RULES_MAX*sizeof(char *));
    memset(p->rxs, 0, WAF_RULES_MAX*sizeof(char *));

    p->idx_cursor = 0;

    return p;
}

void filter_destroy(filter_t *p)
{
    int i = 0;

    if (p->scratch != NULL) {
        hs_free_scratch(p->scratch);
    }

    if (p->db != NULL) {
        hs_free_database(p->db);
    }

    for (i = 0;i < p->idx_cursor;i++ ) {
        free((void *) p->rxs[i]);
    }

    free((void *) p->rxs);
    free((void *) p->ids);
    free((void *) p->flags);

    free(p);
}

static int on_match(unsigned int id, unsigned long long from,
        unsigned long long to, unsigned int flags, void *ctx)
{
    if (ctx) {
        *(int*)ctx = id;
    }

    return 0;
}

int filter_add_rule(filter_t *filter, waf_rule_t *rule)
{
    char *p;
    unsigned int idx;
   
    if (filter == NULL || rule == NULL) {
        return -1;
    }
    
    idx = filter->idx_cursor;
    if (idx == WAF_RULES_MAX) {
        return -1;
    }

    /* rx */
    if ((p = strdup(rule->rx)) == NULL) { 
        return -1;  
    }   
    filter->rxs[idx] = p; 

    /* id */
    filter->ids[idx] = rule->id;

    /* flags */
    filter->flags[idx] = HS_FLAG_CASELESS | HS_FLAG_SINGLEMATCH | HS_FLAG_DOTALL;
    ++filter->idx_cursor;

    return 0;
}

int filter_match(filter_t *filter, char *buff, size_t len, int *matched_rule_id)
{
    hs_error_t err;

    if (filter == NULL || buff == NULL  || len == 0) {
        return -1;
    }

    err = hs_scan(filter->db, buff, len, 0, filter->scratch, on_match, matched_rule_id);
    if (err != HS_SUCCESS) {
        return 0;
    }

    return *matched_rule_id;
}

void filter_show(filter_t *filter)
{
    int i;
    for (i = 0; i< filter->idx_cursor; i++) {
        log_info("db:[%p] scratch:[%p] id:[%d] rx:[%s] idx_cursor:[%d]", 
                filter->db, filter->scratch, filter->ids[i], filter->rxs[i], filter->idx_cursor);
    }
}



