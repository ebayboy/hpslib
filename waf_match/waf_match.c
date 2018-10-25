
#include <stdio.h>
#include <unistd.h>
#include <string.h> 
#include <ctype.h>
#include <stdlib.h>

#include <hs_common.h>
#include <hs_runtime.h>
#include <hs.h>

#include "match.h"
#include "log.h"
#include "waf_match.h"
#include "waf_config.h"

static match_t * find_matcher(waf_match_t *waf_matcher, const char *mz)
{
    match_t *matcher;
    int i;

    if (waf_matcher == NULL || mz == NULL || strlen(mz) == 0) {
        return NULL;
    }

    for (i = 0;i < WAF_MZ_MAX;i++) {
        matcher = waf_matcher->matchers[i];
        if (matcher == NULL) {
            continue;
        }
        if (strcasecmp(matcher->mz, mz) == 0) {
            matcher;
        }
    }

    return NULL;
}

static int waf_match_add_rule(waf_match_t *waf_matcher, waf_config_t *waf_config)
{
    match_t *matcher;
    waf_rule_t *rule;

    if (waf_matcher == NULL || rule == NULL) {
        return -1;
    }

    matcher = find_matcher(waf_matcher, rule->mz);
    if (matcher == NULL) {
        if ((matcher = match_new()) == NULL) {
            return -1;
        }
    }

    match_add_rule(matcher, rule);

    return 0;
}

void waf_match_fini(waf_match_t *waf_match)
{
    int i;
    match_t *matcher = NULL;

    if (waf_match == NULL) {
        return ;
    }

    for (i = 0; i< WAF_MZ_MAX; i++) {
        matcher = waf_match->matchers[i];
        if (matcher == NULL) {
            continue;
        }

        match_destroy(matcher);
    }
}

int waf_match_init(waf_match_t *waf_matcher, waf_config_t *cfg)
{
    match_t *matcher;
    int i;

    memset(waf_matcher, 0, sizeof(waf_match_t));

    waf_matcher->waf_engine = cfg->waf_engine;
    waf_matcher->waf_action = cfg->waf_action;
    strncpy(waf_matcher->waf_id, cfg->waf_id, sizeof(waf_matcher->waf_id));

    for(i = 0; i < WAF_MZ_MAX; i++) {
        if ((matcher = match_new()) == NULL) {
            waf_match_fini(waf_matcher);
            return -1;
        }
        waf_matcher->matchers[i] = matcher;
    }

    return 0;
}

void waf_match_show(waf_match_t *waf_matcher)
{
    int i;
    match_t *matcher;

    if (waf_matcher == NULL) {
        return ;
    }

    log_info("waf_engine:%d\nwaf_action:%d\nwaf_id:[%d]\n");
    for (i = 0; i< WAF_MZ_MAX; i++) {
        match_show(matcher);
    }
}

