
#include <stdio.h>
#include <unistd.h>
#include <string.h> 
#include <ctype.h>
#include <stdlib.h>

#include <hs_common.h>
#include <hs_runtime.h>
#include <hs.h>

#include "match.h"
#include "waf_match.h"

void waf_match_destory(waf_match_t *waf_match)
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

        match_destory(matcher);
    }
}

waf_match_t * waf_match_new(void)
{
    waf_match_t *waf_matcher  = NULL;
    match_t *matcher;
    int i;

    waf_matcher = malloc(sizeof(waf_match_t));
    if (waf_matcher == NULL) {
        return NULL;
    }

    memset(waf_matcher, 0, sizeof(waf_match_t));

    waf_matcher->waf_engine = WAF_ENGINE_OFF;
    waf_matcher->waf_action = WAF_ACT_NONE;

    for(i = 0; i < WAF_MZ_MAX; i++) {
        if ((matcher = match_new()) == NULL) {
            waf_match_destory(waf_matcher);
            return NULL;
        }
        waf_matcher->matchers[i] = matcher;
    }

    return waf_matcher;
}

static match_t* find_matcher(waf_match_t *waf_matcher, const char *mz)
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


