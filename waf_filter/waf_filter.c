#include <string.h> /** for strdup **/
#include <ctype.h>
#include <stdlib.h>

#include <hs_common.h>
#include <hs_runtime.h>
#include <hs.h>

#define MAXRULENUM   10000
/** Define if we use Hyperscan Library **/
#define USE_HYPERSCAN  1

#include "waf_filter.h"
#include "log.h"

#define FILTER_MAGIC 0xFFEEAABB

typedef struct filter_t {
    unsigned int magic;
    hs_database_t *db;
    /* hs_scratch_t *scratch;  // thread level */
    uint32_t  *ids;
    char **patterns;
    uint32_t *flags;
    unsigned int patterns_size;
} filter_t;

void *waf_filter_new(void)
{
    filter_t *p = malloc(sizeof(filter_t));
    memset(p, 0, sizeof(filter_t));

    p->magic = FILTER_MAGIC;

    p->ids = malloc(MAXRULENUM*sizeof(uint32_t));
    memset(p->ids, 0, MAXRULENUM*sizeof(uint32_t));

    p->flags = malloc(MAXRULENUM*sizeof(uint32_t));
    memset(p->flags, 0, MAXRULENUM*sizeof(uint32_t));

    p->patterns = malloc(MAXRULENUM*sizeof(char *));
    memset(p->patterns, 0, MAXRULENUM*sizeof(char *));

    p->patterns_size = 0;

    return p;
}

void waf_filter_destroy(void *h)
{
    unsigned int i = 0;
    filter_t *p = (filter_t *)h;
    if (p->magic != FILTER_MAGIC) {
        return;
    }
    /* scratch mem is managed outside for thread safety */
    /*
       if (p->scratch != NULL) {
       hs_free_scratch(p->scratch);
       }
       */
    if (p->db != NULL) {
        hs_free_database(p->db);
    }
    for (; i < p->patterns_size; i++) {
        free((void *) p->patterns[i]);
    }
    free((void *) p->patterns);
    free((void *) p->ids);
    free((void *) p->flags);
    free(h);
}

static int on_match(unsigned int id, unsigned long long from,
        unsigned long long to, unsigned int flags, void *ctx)
{
    if (ctx) {
        *(uint32_t*)ctx = id;
    }
    return 0;
}

int waf_filter_addrule(void *x, uint32_t id, char *pattern)
{
    filter_t *f = (filter_t *) x;
    char *p;

    if (f->magic != FILTER_MAGIC) {
        return -1;
    }

    unsigned int idx = f->patterns_size;
    if (idx == MAXRULENUM) {
        /* overflow */
        return -1;
    }

    if ((p = strdup(pattern)) == NULL) {
        return -1;
    }

    f->ids[idx] = id;
    f->patterns[idx] = p;
    f->flags[idx] = HS_FLAG_CASELESS | HS_FLAG_SINGLEMATCH | HS_FLAG_DOTALL;
    ++f->patterns_size;
    return 0;

}

int waf_filter_compile(void *x) {
    filter_t *f = (filter_t *) x;
    hs_compile_error_t *compileErr = NULL;
    hs_error_t err;

    if (f->magic != FILTER_MAGIC) {
        return -1;
    }

    err = hs_compile_multi((const char *const *)f->patterns, f->flags, f->ids,
            f->patterns_size, HS_MODE_BLOCK, NULL, &f->db, &compileErr);

    if (err != HS_SUCCESS) {
        if (compileErr->expression < 0) {
            WAF_LOG(WAF_LOG_ERR, "%s", compileErr->message);
        } else {
            WAF_LOG(WAF_LOG_ERR, "ERROR: Pattern '%d' failed with error '%s'",
                    f->ids[compileErr->expression], compileErr->message);
        }
        hs_free_compile_error(compileErr);
        return -1;
    }

    /* scratch alloc thread level */
    return 0;
}

int waf_filter_match(void *h, hs_scratch_t *scratch, char *buff, size_t len,
        uint32_t *matched_rule_id)
{
    filter_t *p = (filter_t *) h;
    hs_error_t err;

    if (p->magic != FILTER_MAGIC) {
        return 0;
    }

    err = hs_scan(p->db, buff, len, 0, scratch, on_match, matched_rule_id);
    if (err != HS_SUCCESS) {
        return 0;
    }
    return *matched_rule_id;
}

int waf_filter_serialize(void *h, char **ptr, size_t *len)
{
    filter_t *p = (filter_t *) h;
    if (hs_serialize_database(p->db, ptr, len) != HS_SUCCESS) {
        return -1;
    }
    return 0;
}

int waf_filter_deserialize(void *h, char *ptr, size_t len)
{
    filter_t *p = (filter_t *) h;
    if (hs_deserialize_database(ptr, len, &(p->db)) != HS_SUCCESS) {
        return -1;
    }

    return 0;
    /* scratch alloc thread level */
}

int waf_filter_alloc_scratch(void *h, void **pp_scratch) {
    filter_t *p = (filter_t *) h;
    hs_error_t err = hs_alloc_scratch(p->db, (hs_scratch_t **)pp_scratch);
    if (err != HS_SUCCESS) {
        return -1;
    }
    return 0;
}

