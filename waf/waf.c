
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
#include "waf.h"

#define WAF_MZ_URI              "$uri"
#define WAF_MZ_U_URI            "$u_uri"

#define WAF_MZ_ARGS             "$args"
#define WAF_MZ_U_ARGS           "$u_args"

#define WAF_MZ_REQ_BODY         "$request_body"
#define WAF_MZ_U_REQ_BODY       "$u_request_body"




typedef struct {
    size_t          len;
    unsigned char  *data;
} str_t;

typedef struct {
    list_head_t list;
    str_t key;
    str_t value;
} param_node_t;

typedef struct {
    http_method_e method;
    str_t uri;
    str_t args;
    str_t request_body;

    list_head_t headers_head; /* var in headers */
} waf_data_t;

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

scan_result_e waf_match_ori(str_t *str, int *matched_rule_id, const char *mz)
{
    unsigned char *buf = NULL;
    int dlen = 0;
    scan_result_e rc = SCAN_NOT_MATCHED;

    if (str == NULL ||
            str->data == NULL ||
            str->len == 0 ||
            matched_rule_id == NULL) {
        return  SCAN_ERROR;
    }

    if ((buf = malloc(str->len)) == NULL) {
        return SCAN_ERROR;
    }

    /* decode */
    dlen = decodeURI(buf, str->len, str->data, str->len);
    rc = waf_match_match(&waf->waf_match, mz, buf, dlen, matched_rule_id);

out:
    if (buf) {
        free(buf);
    }
    
    return rc;
}

static waf_match_unparsed(waf_data_t *data, int *matched_rule_id)
{
    int rc = 0;

    /* match uri */
    if (data->uri.data && data->uri.len > 0) {
        rc = waf_match_ori(&data->uri, matched_rule_id, WAF_MZ_URI);
        if (rc == SCAN_MATCHED) {
            return rc;
        }
    }

    /* match args */
    if (data->args.data && data->args.len > 0) {
        rc = waf_match_ori(&data->args, matched_rule_id, WAF_MZ_ARGS);
        if (rc == SCAN_MATCHED) {
            return rc;
        }
    }

    /* request body */
    if (data->request_body.data && data->request_body.len > 0) {
        rc = waf_match_ori(&data->request_body, matched_rule_id, WAF_MZ_REQ_BODY);
        if (rc == SCAN_MATCHED) {
            return rc;
        }
    }

    return rc;
}

static waf_match_parsed(waf_data_t *data, int *matched_rule_id)
{
    int rc = 0;

    /* match uri */
    if (data->uri.data && data->uri.len > 0) {
        rc = waf_match_ori(&data->uri, matched_rule_id, WAF_MZ_URI);
        if (rc == SCAN_MATCHED) {
            return rc;
        }
    }

    return rc;
}


scan_result_e waf_match(void *waf_data, int *matched_rule_id)
{
    waf_data_t *data  = NULL;
    int rc = SCAN_NOT_MATCHED;

    if (waf_data == NULL || matched_rule_id == NULL) {
        log_error("input error.");
        return -1;
    }

    data = (waf_data_t *)waf_data;

    /* unparsed */
    if ((rc = waf_match_unparsed(data, matched_rule_id)) == SCAN_MATCHED) {
        return rc;
    }

    /* parsed */
    if ((rc = waf_match_parsed(data, matched_rule_id)) == SCAN_MATCHED) {
        return rc;
    }

    return SCAN_NOT_MATCHED;
}

void * waf_data_create(
        http_method_e method, 
        unsigned char  *uri, size_t uri_len,
        unsigned char *args, size_t args_len,
        unsigned char *request_body, size_t req_len)
{
    waf_data_t *data;

    if((data = malloc(sizeof(waf_data_t))) == NULL) {
        return NULL;
    }
    memset(data, 0, sizeof(waf_data_t));

    INIT_LIST_HEAD(&data->headers_head);

    data->method = method;

    data->uri.data = uri;
    data->uri.len = uri_len;

    data->args.data = args;
    data->args.len = args_len;

    data->request_body.data = request_body;
    data->request_body.len = req_len;

    return data;
}

int waf_data_add_param(void *waf_data,
        param_type_t type,
        unsigned char *key_data, size_t key_len,
        unsigned char *value_data, size_t value_len)
{
    param_node_t *node = NULL;
    waf_data_t *data = waf_data;

    if (data == NULL || key_data == NULL || key_len ==0
            || value_data == NULL || value_len == 0) {
        return -1;
    }

    if (type != PARAM_HDR_TYPE) {
        log_error("input type error type:%d", type);
        return -1;
    }

    /* new node */
    node = malloc(sizeof(param_node_t));
    if (node == NULL) {
        return -1;
    }
    memset(node, 0, sizeof(param_node_t));

    /* new key */
    node->key.data = malloc(key_len);
    if (node->key.data == NULL) {
        free(node);
        return -1;
    }
    memset(node->key.data, 0, key_len);
    memcpy(node->key.data, key_data, key_len);
    node->key.len = key_len;

    /* new value */
    node->value.data = malloc(node->value.len);
    if (node->value.data == NULL) {
        if (node->key.data) {
            free(node->key.data);
        }

        free(node);
        return -1;
    }
    memset(node->value.data, 0, node->value.len);
    memcpy(node->value.data, value_data, value_len);
    node->value.len = value_len;

    /* add node to list */
    if (type == PARAM_HDR_TYPE) {
        list_add_tail(&node->list, &data->headers_head);
    } 

    return 0;
}

static void waf_header_free(param_node_t *header)
{
    if(header == NULL) {
        return ;
    }

    if (header->key.data) {
        free(header->key.data);
        header->key.len = 0;
    }

    if (header->value.data) {
        free(header->value.data);
        header->value.len = 0;
    }

    free(header);
}

static void waf_headers_free(list_head_t *headers_head)
{
    param_node_t *node = NULL;

    if (headers_head == NULL) {
        return ;
    }

    if (list_empty(headers_head)) {
        return ;
    }

    list_for_each_entry(node, headers_head, list) {
        list_del(&node->list);
        waf_header_free(node);
    }

    return ;
}

void waf_data_destroy(void *waf_data)
{
    waf_data_t *data = waf_data;

    if (data == NULL) {
        return;
    }
    
    waf_headers_free(&data->headers_head);

    free(data);
}


