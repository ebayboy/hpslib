
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "waf.h"

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

    return 0;
}


int waf_init(const char *logfile)
{
    waf_t waf;

    memset(&waf, 0, sizeof(waf));


    if (waf_logger_init(logfile, &waf) == -1) {
        return -1;
    }


    return 0;
}
