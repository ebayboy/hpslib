
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

int waf_init(const char *logfile, const char *waf_config_name)
{
    memset(&waf, 0, sizeof(waf));

    /* logger init */
    if (waf_logger_init(logfile, &waf) == -1) {
        return -1;
    }

    /* config init */
    waf_config_init(waf_config_name, &waf.waf_config);

    return 0;
}

int waf_fini(void)
{
    if (waf.log_fp != NULL) {
        fclose(waf.log_fp);
    }

    return 0;
}
