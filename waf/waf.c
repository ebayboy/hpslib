
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "log.h"
#include "common.h"
#include "match.h"
#include "waf_match.h"
#include "filter.h"
#include "waf_config.h"
#include "waf_config.h"

typedef struct {
    FILE *log_fp;
    waf_config_t waf_config;
    waf_match_t waf_match;
} waf_t;

static waf_t *waf = NULL;

static int waf_logger_init(const char *logfile, waf_t *waf)
{
    FILE *fp = NULL;

    if (logfile == NULL || waf == NULL) {
        return -1;
    }

    if ((fp = fopen(logfile, "a+")) == NULL) {
        return -1;
    }

    waf->log_fp = fp;

    log_set_fp(waf->log_fp);
#ifndef DEBUG
    log_set_quiet(1);
#endif

    return 0;
}

void waf_fini(void)
{
    /* log destroy */
    if (waf->log_fp != NULL) {
        fclose(waf->log_fp);
    }

    waf_match_fini(&waf->waf_match);
}

int waf_init(const char *logfile, const char *waf_config_name)
{

    if (waf == NULL) {
        if ((waf = malloc(sizeof(waf_t))) == NULL) {
            log_error("waf malloc error!");
            return -1;
        }
        memset(waf, 0, sizeof(waf_t));
        if (waf == NULL) {
            return -1;
        }
    }

    if (waf_logger_init(logfile, waf) == -1) {
        goto error;
    }

    if (waf_config_init(waf_config_name, &waf->waf_config)) {
        goto error;
    }
    
    waf_match_init(&waf->waf_match, &waf->waf_config);

    return 0;

error:

    waf_fini();
    return -1;
}

void waf_show()
{
    if (waf == NULL) {
        return;
    }

    log_info("log_fp:%p", waf->log_fp);
    waf_config_show(&waf->waf_config);
    waf_match_show(&waf->waf_match);
}

int waf_match(const unsigned char *mz,
        const unsigned char *buff,
        size_t blen, 
        int *matched_rule_id)
{
    if (mz == NULL 
            || buff == NULL
            || blen == 0
            || matched_rule_id == NULL
            || strlen(mz) == 0
            || strlen(buff) == 0) {
        return -1;
    }

    return waf_match_match(&waf->waf_match, 
            mz, buff, blen, matched_rule_id);
}

