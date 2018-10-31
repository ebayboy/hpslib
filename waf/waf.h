#ifndef __WAF_H
#define __WAF_H

#include "list.h"

/* ================= WAF module ==================== */
typedef enum {
    SCAN_ERROR = -1,
    SCAN_NOT_MATCHED = 0,
    SCAN_MATCHED = 1,
} scan_result_e;

int waf_init(const char *log_fname, const char *cfg_fname);

void waf_show(void);

void waf_fini(void);

scan_result_e waf_match(void *waf_data, int *matched_rule_id);

/* =============== waf data API ==================== */
typedef enum {
    HTTP_UNKNOWN,
    HTTP_GET,
    HTTP_HEAD,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_MKCOL,
    HTTP_COPY,
    HTTP_MOVE,
    HTTP_OPTIONS,
    HTTP_PROPFIND,
    HTTP_PROPPATCH,
    HTTP_LOCK,
    HTTP_UNLOCK,
    HTTP_PATCH,
    HTTP_TRACE
} http_method_e;

typedef enum {
    PARAM_HDR_TYPE = 0,
    PARAM_VAR_TYPE = 1
} param_type_t;

void * waf_data_create(
        http_method_e method,
        unsigned char  *uri, size_t uri_len,
        unsigned char *args, size_t args_len,
        unsigned char *request_body, size_t req_len);

void waf_data_destroy(void *waf_data);

int waf_data_add_param(void *waf_data,
        param_type_t type,
        unsigned char *key_data, size_t key_len,
        unsigned char *value_data, size_t value_len);

#endif

