
#include <stdio.h>
#include <unistd.h>
#include <string.h> 
#include <ctype.h>
#include <stdlib.h>

#include <hs_common.h>
#include <hs_runtime.h>
#include <hs.h>

#include "log.h"
#include "match.h"
#include "filter.h"
#include "waf_config.h"

void match_destroy(match_t *matcher)
{
    if (matcher == NULL) {
        return;
    }

    if (matcher->filter) {
        filter_destroy(matcher->filter);
    }

    free(matcher);
}

match_t * match_new()
{
    match_t *new;

    new = malloc(sizeof(match_t));
    if (new == NULL) {
        return NULL;
    }
    memset(new, 0, sizeof(match_t));

    new->filter = filter_new();
    if (new->filter == NULL) {
        match_destroy(new);
        return NULL;
    }

    return new;
}

int match_add_rule(match_t *matcher, waf_rule_t *rule)
{
    if (matcher == NULL || rule == NULL || matcher->filter == NULL) {
        return -1;
    }

    return filter_add_rule(matcher->filter, rule);
}

void match_show(match_t *matcher)
{
    log_info("mz:[%s] mz_hash:[%u]\n", matcher->mz, matcher->mz_hash);
    filter_show(matcher->filter);
}

int match_build(match_t *matcher)
{
    if (matcher == NULL || matcher->filter == NULL) {
        return -1;
    }
   
    return filter_build(matcher->filter);
}


int match_match(match_t *matcher, const char *buff, size_t len, int *matched_rule_id)
{
    if (matcher == NULL || buff == NULL 
            || len == 0  || matched_rule_id == NULL) {
        return -1;
    }
    return filter_match(matcher->filter, buff, len, matched_rule_id);
}

