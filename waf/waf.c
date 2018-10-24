
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "waf.h"

waf_t waf;

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

int waf_fini(void)
{
    /* log destroy */
    if (waf.log_fp != NULL) {
        fclose(waf.log_fp);
    }

    return 0;
}

int waf_init(const char *logfile, const char *waf_config_name)
{
    memset(&waf, 0, sizeof(waf));

    /* logger init */
    if (waf_logger_init(logfile, &waf) == -1) {
        goto error;
    }

    /* config init */
    if (waf_config_init(waf_config_name, &waf.waf_config)) {
        goto error;
    }
    
    /* add config to waf_match */

    return 0;

error:

    waf_fini();
    return -1;
}

