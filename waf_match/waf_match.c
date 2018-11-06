
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

match_t * find_matcher(waf_match_t *waf_matcher, const char *mz)
{
    match_t *matcher;
    int i;

    if (waf_matcher == NULL || mz == NULL || strlen(mz) == 0) {
        return NULL;
    }

    for (i = 0;i < waf_matcher->matcher_cursor;i++) {
        matcher = waf_matcher->matchers[i];
        if (matcher == NULL) {
            continue;
        }
        if (strcasecmp(matcher->mz, mz) == 0) {
            return matcher;
        }
    }

    return NULL;
}

static void waf_match_decode_type_set(match_t *matcher)
{
#define SET_DECODE_TYPE(x)      \
    do {        \
        matcher->do_parse = 1;          \
        matcher->do_decode = 1;         \
        matcher->decode_type[x] = x;    \
    } while(0); 

    if (strcasecmp(matcher->mz, WAF_MZ_U_GET_KEY) == 0) {
        SET_DECODE_TYPE(NORMALDATA);
        SET_DECODE_TYPE(URLDECODE_KEY);
    } else if (strcasecmp(matcher->mz, WAF_MZ_U_GET_VALUE) == 0) {
        SET_DECODE_TYPE(NORMALDATA);
        SET_DECODE_TYPE(URLDECODE_VALUE);
    } else if (strcasecmp(matcher->mz, WAF_MZ_U_COOKIE_KEY) == 0) {
        SET_DECODE_TYPE(NORMALDATA);
        SET_DECODE_TYPE(COOKIE_KEY);
    } else if (strcasecmp(matcher->mz, WAF_MZ_U_COOKIE_VALUE) == 0) {
        SET_DECODE_TYPE(NORMALDATA);
        SET_DECODE_TYPE(COOKIE_VALUE);
    } else if (strcasecmp(matcher->mz, WAF_MZ_ARGS_KEY) == 0) {
        SET_DECODE_TYPE(NORMALDATA);
        SET_DECODE_TYPE(JSON_KEY);
        SET_DECODE_TYPE(XML_KEY);
        SET_DECODE_TYPE(MULTIPART_KEY);
        SET_DECODE_TYPE(COOKIE_KEY);
        SET_DECODE_TYPE(URLDECODE_KEY);

        matcher->do_decode = 0;
    } else if (strcasecmp(matcher->mz, WAF_MZ_ARGS_VALUE) == 0) {
        SET_DECODE_TYPE(NORMALDATA);
        SET_DECODE_TYPE(JSON_VALUE);
        SET_DECODE_TYPE(XML_VALUE);
        SET_DECODE_TYPE(MULTIPART_VALUE);
        SET_DECODE_TYPE(COOKIE_VALUE);
        SET_DECODE_TYPE(URLDECODE_VALUE);

        matcher->do_decode = 0;
    } else if (strcasecmp(matcher->mz, WAF_MZ_U_ARGS_KEY) == 0) {
        SET_DECODE_TYPE(NORMALDATA);
        SET_DECODE_TYPE(JSON_KEY);
        SET_DECODE_TYPE(XML_KEY);
        SET_DECODE_TYPE(MULTIPART_KEY);
        SET_DECODE_TYPE(COOKIE_KEY);
        SET_DECODE_TYPE(URLDECODE_KEY);
    } else if (strcasecmp(matcher->mz, WAF_MZ_U_ARGS_VALUE) == 0) {
        SET_DECODE_TYPE(NORMALDATA);
        SET_DECODE_TYPE(JSON_VALUE);
        SET_DECODE_TYPE(XML_VALUE);
        SET_DECODE_TYPE(MULTIPART_VALUE);
        SET_DECODE_TYPE(URLDECODE_VALUE);
        SET_DECODE_TYPE(COOKIE_VALUE);
    } else if (strcasecmp(matcher->mz, WAF_MZ_U_POST_KEY) == 0) {
        SET_DECODE_TYPE(NORMALDATA);
        SET_DECODE_TYPE(JSON_KEY);
        SET_DECODE_TYPE(XML_KEY);
        SET_DECODE_TYPE(MULTIPART_KEY);
        SET_DECODE_TYPE(URLDECODE_KEY);
    } else if (strcasecmp(matcher->mz, WAF_MZ_U_POST_VALUE) == 0) {
        SET_DECODE_TYPE(NORMALDATA);
        SET_DECODE_TYPE(JSON_VALUE);
        SET_DECODE_TYPE(XML_VALUE);
        SET_DECODE_TYPE(MULTIPART_VALUE);
        SET_DECODE_TYPE(URLDECODE_VALUE);
    } else if (strcasecmp(matcher->mz, WAF_MZ_FILE_NAME) == 0) {
        SET_DECODE_TYPE(NORMALDATA);
        SET_DECODE_TYPE(MULTIPART_FILENAME);
    } else if (strcasecmp(matcher->mz, WAF_MZ_FILE_CONTENT) == 0) {
        SET_DECODE_TYPE(NORMALDATA);
        SET_DECODE_TYPE(MULTIPART_FILECONTENT);
    } else if (strcasecmp(matcher->mz, WAF_MZ_U_REQUEST_BODY) == 0) {
        SET_DECODE_TYPE(NORMALDATA);
        SET_DECODE_TYPE(JSON_KEY);
        SET_DECODE_TYPE(XML_KEY);
        SET_DECODE_TYPE(MULTIPART_KEY);
        SET_DECODE_TYPE(COOKIE_KEY);
        SET_DECODE_TYPE(URLDECODE_KEY);

        SET_DECODE_TYPE(JSON_VALUE);
        SET_DECODE_TYPE(XML_VALUE);
        SET_DECODE_TYPE(MULTIPART_VALUE);
        SET_DECODE_TYPE(URLDECODE_VALUE);
        SET_DECODE_TYPE(COOKIE_VALUE);

        SET_DECODE_TYPE(MULTIPART_FILENAME);
        SET_DECODE_TYPE(MULTIPART_FILECONTENT);
    }
#undef SET_DECODE_TYPE
}

static int waf_match_add_rules(waf_match_t *waf_matcher, waf_config_t *waf_config)
{
    match_t *matcher;
    waf_rule_t *rule;
    int i;
    char buf[WAF_RULE_MZS_LEN] = {0};
    char *ptrim, *token;
    unsigned char mz_hash_str[WAF_MZ_MAX] = {0};

    if (waf_matcher == NULL || rule == NULL) {
        return -1;
    }

    for (i = 0; i < waf_config->idx_cursor; i++ ) {
        rule = &waf_config->rules[i];

        strncpy(buf, rule->mz, sizeof(buf) - 1);

        log_info("buf:[%s]", buf);

        token = strtok(buf,",");

        while(token) {
            ptrim = token;
            strim(ptrim);
            if (ptrim == NULL) {
                log_error("ptrim mz=[%s]", ptrim);
                return -1;
            }
            log_info("token:[%s] ptrim:[%s] waf_matcher->cursor:[%d]", 
                    token, ptrim, waf_matcher->matcher_cursor);


            /*check matcher */
            matcher = find_matcher(waf_matcher, ptrim);
            if (matcher == NULL) {
                if (waf_matcher->matcher_cursor + 1 >= WAF_MZ_MAX) {
                    log_error("too many match zones, max is [%d]", WAF_MZ_MAX);
                    return -1;
                }

                if ((matcher = match_new()) == NULL) {
                    return -1;
                }

                /* default don't parse && decode */
                matcher->do_parse = 0;
                matcher->do_decode = 0;

                strncpy(matcher->mz, ptrim, sizeof(matcher->mz) - 1);
                matcher->mz_hash = waf_hash_strlow(
                        mz_hash_str, matcher->mz, strlen(matcher->mz));
                waf_matcher->matchers[waf_matcher->matcher_cursor++] = matcher;

                waf_match_decode_type_set(matcher);
            }

            match_add_rule(matcher, rule, ptrim);
            log_info("id:[%d] macher->mz:[%s]", rule->id, matcher->mz);
            token = strtok(NULL,",");
        }
    }

    return 0;
}

static int waf_match_build(waf_match_t *waf_matcher)
{
    match_t *matcher;
    int i;

    if (waf_matcher == NULL) {
        return -1;
    }

    for (i = 0; i < waf_matcher->matcher_cursor; i++ ) {
        matcher = waf_matcher->matchers[i];
        if (matcher == NULL) {
            log_error("matcher NULL error.");
            return -1;
        }

        if (match_build(matcher) == -1) {
            log_error("match_build error");
            return -1;
        }
    }

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

    if (waf_matcher == NULL || cfg == NULL) {
        return 0;
    }

    memset(waf_matcher, 0, sizeof(waf_match_t));

    waf_matcher->matcher_cursor = 0;
    waf_matcher->waf_engine = cfg->waf_engine;
    waf_matcher->waf_action = cfg->waf_action;
    strncpy(waf_matcher->waf_id, cfg->waf_id, sizeof(waf_matcher->waf_id));

    if (waf_match_add_rules(waf_matcher, cfg) == -1) {
        log_error("waf_match_add_rules -1");
        return -1;
    }

    if (waf_match_build(waf_matcher) == -1) {
        log_error("waf_match_build error.");
        return -1;
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

    log_info("waf_engine:%d\nwaf_action:%d\nwaf_id:[%s] waf_match_cursor:%d\n",
            waf_matcher->waf_engine,
            waf_matcher->waf_action,
            waf_matcher->waf_id,
            waf_matcher->matcher_cursor);

    for (i = 0; i< waf_matcher->matcher_cursor; i++) {
        matcher = waf_matcher->matchers[i];
        if (matcher) {
            match_show(matcher);
        }
    }
}

int waf_match_match(waf_match_t *waf_matcher, 
        const unsigned char *mz, 
        size_t mz_len,
        unsigned int mz_hash,
        const unsigned char *buff, 
        size_t blen, 
        int *matched_rule_id)
{
    match_t *matcher;
    unsigned int i, hash = 0;
    unsigned char mz_hash_str[WAF_RULE_MZ_LEN] = {0};

    if (mz_hash == 0) {
        hash = waf_hash_strlow(mz_hash_str, mz, mz_len);
    }

    if (mz == NULL || buff == NULL 
            || matched_rule_id == NULL
            || waf_matcher == NULL) {
        return -1;
    }

    if (mz_len > WAF_MZ_MAX) {
        log_error("mz length %d > WAF_MZ_MAX %d", strlen(mz), WAF_MZ_MAX);
        return -1;
    }

    for (i = 0 ; i < waf_matcher->matcher_cursor; i++ ) {
        matcher = waf_matcher->matchers[i];
        if (matcher == NULL) {
            continue;
        }

        if (hash != matcher->mz_hash) {
            continue;
        }
        
        return match_match(matcher, buff, blen, matched_rule_id);
    }


    return 0;
}

