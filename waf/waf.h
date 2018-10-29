#ifndef __WAF_H
#define __WAF_H

#include "list.h"

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

typedef struct {
    size_t          len;
    unsigned char  *data;
} str_t;

typedef struct {
    list_head_t list;
    str_t key;
    str_t value;
} header_node_t;

typedef struct {
    list_head_t list;
    str_t key;
    str_t value;
} var_node_t;

typedef struct {
    http_method_e method;
    str_t uri;
    str_t args;
    str_t request_body;

    void * headers_head; /* var in headers */
    void * vars_head;    /* var not in header, self defined var*/
} waf_data_t;

int waf_header_add(waf_data_t *data, str_t key, str_t value);
int waf_var_add(waf_data_t *data, str_t key, str_t value);



int waf_init(const char *log_fname, const char *cfg_fname);

void waf_fini(void);

void waf_show();

int waf_match(const unsigned char *mz,
        const unsigned char *buff,
        size_t blen, 
        int *matched_rule_id);

#endif

