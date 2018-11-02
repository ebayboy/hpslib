
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


/* mz <==> header */
/* mz <==> var */

/* 
var->key   mz 
var->value  hdr
*/

/* all mz */
/* uri */
#define WAF_MZ_URI                  "$uri"
#define WAF_MZ_ARGS                 "$args"
#define wAF_MZ_HTTP_URL             "$url"  /* var */
#define WAF_MZ_REQUEST_URI          "$request_uri"
#define WAF_MZ_REQUEST_BODY         "$request_body"
#define WAF_MZ_HTTP_REFERER         "$http_referer"
#define WAF_MZ_HTTP_USER_AGENT      "$http_user_agent"

#define wAF_MZ_HTTP_COOKIE          "$http_cookie"
#define WAF_MZ_REQUEST_HEADERS      "$request_headers"

/* html decode */
#define WAF_MZ_U_URI                "$u_uri"
#define WAF_MZ_U_ARGS               "$u_args"
#define WAF_MZ_U_REQUEST_URI        "$u_request_uri"
#define WAF_MZ_U_REQUEST_BODY       "$u_request_body"
#define WAF_MZ_U_HTTP_REFERER       "$u_http_referer"
#define WAF_MZ_U_HTTP_USER_AGENT    "$u_http_user_agent"
#define wAF_MZ_U_HTTP_URL           "$u_url"
#define wAF_MZ_U_HTTP_COOKIE        "$u_http_cookie"
#define WAF_MZ_U_REQUEST_HEADERS    "$u_request_headers"

/* define decode */
#define WAF_MZ_ARGS_KEY             "$args_key"
#define WAF_MZ_ARGS_VALUE           "$args_value"
#define WAF_MZ_U_COOKIE_KEY         "$u_cookie_key"
#define WAF_MZ_U_COOKIE_VALUE       "$u_cookie_value"
#define WAF_MZ_U_ARGS_KEY           "$u_args_key"
#define WAF_MZ_U_ARGS_VALUE         "$u_args_value"
#define WAF_MZ_U_POST_KEY           "$u_post_key"
#define WAF_MZ_U_POST_VALUE         "$u_post_value"
#define WAF_MZ_U_FILENAME           "$file_name"
#define WAF_MZ_U_FILE_CONTENT       "$file_content"

#define WAF_MZ_UNESCAPT_PREFIX      "u_"

typedef struct {
    size_t          len;
    unsigned char  *data;
} str_t;

typedef struct {
    list_head_t list;
    str_t key;
    unsigned int key_hash;  /* used by hdr */
    str_t value;
    unsigned int value_hash; /* used by var */
} waf_param_t;

typedef struct {
    http_method_e method;
    str_t uri;
    str_t args;
    str_t request_body;

    list_head_t headers_head;
    list_head_t vars_head;   /* not used now */
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

scan_result_e waf_match_ori(str_t *str, int *matched_rule_id, str_t *mz)
{
    scan_result_e rc = SCAN_NOT_MATCHED;

    if (str == NULL ||
            str->data == NULL ||
            str->len == 0 ||
            matched_rule_id == NULL) {
        return  SCAN_ERROR;
    }

    rc = waf_match_match(&waf->waf_match, mz->data, 
            mz->len, str->data, str->len, matched_rule_id);
    return rc;
}

scan_result_e waf_match_unescapted(str_t *str, int *matched_rule_id,  str_t *mz)
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

    dlen = decodeURI(buf, str->len, str->data, str->len);
    rc = waf_match_match(&waf->waf_match, 
            mz->data, mz->len, buf, dlen, matched_rule_id);

    if (buf) {
        free(buf);
    }
    
    return rc;
}

static int waf_match_headers_all(waf_data_t *data, int *matched_rule_id)
{
    int rc = 0;
    waf_param_t *hdr = NULL, *var = NULL;
    list_for_each_entry(var, &data->vars_head, list) {
        if (var->key.data == NULL || var->value.data == NULL 
                || var->value.data == 0 || var->value.len == 0) {
            continue;
        }

        if (var->key.len > 2 && strncasecmp(var->key.data, 
                    WAF_MZ_UNESCAPT_PREFIX, 
                    strlen(WAF_MZ_UNESCAPT_PREFIX)) == 0) {
            continue;
        }

        list_for_each_entry(hdr, &data->headers_head, list) {
            if (hdr->key.data == NULL || hdr->value.data == NULL 
                    || hdr->value.data == 0 || hdr->value.len == 0) {
                if (hdr->value.len != var->value.len) {
                    continue;
                }
                if (strncasecmp(var->value.data, hdr->value.data, var->value.len) != 0) {
                    continue; 
                }
                /* match ori */
                rc = waf_match_ori(&hdr->key, matched_rule_id, &var->key /* mz */);
                if (rc == SCAN_MATCHED) {
                    return rc;
                }
            }
        }
    }

    return rc;
}

static int waf_match_headers_unescapted_all(waf_data_t *data, int *matched_rule_id)
{
    int rc = 0;
    waf_param_t *hdr = NULL, *var = NULL;

    list_for_each_entry(var, &data->vars_head, list) {
        if (var->key.len < 2) {
            continue;
        }

        /* continue not u_ start */
        if (strncasecmp(var->key.data, 
                    WAF_MZ_UNESCAPT_PREFIX, 
                    strlen(WAF_MZ_UNESCAPT_PREFIX)) != 0) {
            continue;
        }

        if (var->key.data == NULL || var->value.data == NULL 
                || var->value.data == 0 || var->value.len == 0) {
            continue;
        }

        list_for_each_entry(hdr, &data->headers_head, list) {
            if (hdr->key.data == NULL || hdr->value.data == NULL 
                    || hdr->value.data == 0 || hdr->value.len == 0) {
                if (hdr->value.len != var->value.len) {
                    continue;
                }

                if (var->value_hash != hdr->key_hash) {
                    continue; 
                }

                rc = waf_match_unescapted(&hdr->key, matched_rule_id, &var->key /* mz */);
                if (rc == SCAN_MATCHED) {
                    return rc;
                }
            }
        }
    }

    return rc;
}


static int waf_match_ori_all(waf_data_t *data, int *matched_rule_id)
{
    int rc = 0;
    str_t mz;

    /* match uri */
    if (data->uri.data && data->uri.len > 0) {
        mz.data = WAF_MZ_URI;
        mz.len = strlen(WAF_MZ_URI);
        rc = waf_match_ori(&data->uri, matched_rule_id, &mz);
        if (rc == SCAN_MATCHED) {
            return rc;
        }
    }

    /* match args */
    if (data->args.data && data->args.len > 0) {
        mz.data = WAF_MZ_ARGS;
        mz.len = strlen(WAF_MZ_ARGS);
        rc = waf_match_ori(&data->args, matched_rule_id, &mz);
        if (rc == SCAN_MATCHED) {
            return rc;
        }
    }

    /* request body */
    if (data->request_body.data && data->request_body.len > 0) {
        mz.data = WAF_MZ_REQUEST_BODY;
        mz.len = strlen(WAF_MZ_REQUEST_BODY);
        rc = waf_match_ori(&data->request_body, matched_rule_id, &mz);
        if (rc == SCAN_MATCHED) {
            return rc;
        }
    }

    return rc;
}

/* TODO: ? */
static int ngx_http_waf_match_handler (
        int type,
        char *dec_out,
        int dec_out_len)
{
    int rc = 0;
#if 0 
    struct passThrough *pt = (struct passThrough  *)passThrough;
    waf_context_t *ctx;
    int ret = 0, i;

    if (dec_out == NULL
            || dec_out_len <= 0
            || dec_out_len > DECOUT_SIZE_MAX ) {
        return ret;
    }

    if ((ctx = waf_ctx_get(pt->r)) == NULL || pt == NULL) {
        return ret;
    }

    for (i = 0; i < DECODE_TYPE_SIZE; i++) {
        if (pt->m->decode_type[i] == type) {
            ret += pt->m->do_match((char*)dec_out, dec_out_len, *pt->set_result);
        }
    }
#endif

    return rc;
}

/* 自适应解码  */
static waf_match_decode_all(waf_data_t *data, int *matched_rule_id)
{
    int rc = 0, dlen;
    unsigned char *decode = NULL;

#if 0
    /* match u_uri */
    if (data->uri.data && data->uri.len > 0) {
        rc = waf_match_match(&waf->waf_match, mz->data, 
                mz->len, str->data, str->len, matched_rule_id);
        if (rc == SCAN_MATCHED) {
            return rc;
        }
    }

    ret += ngx_http_waf_data_decode(
            (char *)cl->buf->pos, 
            size, 
            ngx_http_waf_match_handler, 
            &pt, 
            NULL, /* content_type */
            do_unbase64,  
            do_unescaped,
            do_gbk2utf8);
#endif

    return rc;
}

static int waf_match_unescapted_all(waf_data_t *data, int *matched_rule_id)
{
    int rc = 0;
    str_t mz;

    if (data->uri.data && data->uri.len > 0) {
        mz.data = WAF_MZ_U_URI;
        mz.len = strlen(WAF_MZ_U_URI);
        rc = waf_match_unescapted(&data->uri, matched_rule_id, &mz);
        if (rc == SCAN_MATCHED) {
            return rc;
        }
    }

    if (data->args.data && data->args.len > 0) {
        mz.data = WAF_MZ_U_ARGS;
        mz.len = strlen(WAF_MZ_U_ARGS);
        rc = waf_match_unescapted(&data->args, matched_rule_id, &mz);
        if (rc == SCAN_MATCHED) {
            return rc;
        }
    }

    if (data->request_body.data && data->request_body.len > 0) {
        mz.data = WAF_MZ_U_REQUEST_BODY;
        mz.len = strlen(WAF_MZ_U_REQUEST_BODY);
        rc = waf_match_unescapted(&data->request_body, matched_rule_id, &mz);
        if (rc == SCAN_MATCHED) {
            return rc;
        }
    }

    return 0;
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

    /* ori */
    if ((rc = waf_match_headers_all(data, matched_rule_id)) == SCAN_MATCHED) {
        return rc;
    }
    if ((rc = waf_match_ori_all(data, matched_rule_id)) == SCAN_MATCHED) {
        return rc;
    }

    /* escapted */
    if ((rc = waf_match_unescapted_all(data, matched_rule_id)) == SCAN_MATCHED) {
        return rc;
    }
    if ((rc = waf_match_headers_unescapted_all(data, matched_rule_id)) == SCAN_MATCHED) {
        return rc;
    }

    /* decode */
    if ((rc = waf_match_decode_all(data, matched_rule_id)) == SCAN_MATCHED) {
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
    INIT_LIST_HEAD(&data->vars_head);

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
    waf_param_t *node = NULL;
    waf_data_t *data = waf_data;
    unsigned char mz_hash_str[WAF_MZ_MAX] = {0};

    if (data == NULL || key_data == NULL || key_len ==0
            || value_data == NULL || value_len == 0) {
        return -1;
    }

    if (type != PARAM_HDR_TYPE && type != PARAM_VAR_TYPE) {
        log_error("input type error type:%d", type);
        return -1;
    }

    /* new node */
    node = malloc(sizeof(waf_param_t));
    if (node == NULL) {
        return -1;
    }
    memset(node, 0, sizeof(waf_param_t));

#define DATA_SET_ATTR(x)    \
    node->x.data = malloc(x##_len);   \
    if (node->x.data == NULL) { \
        free(node); \
        return -1;  \
    }       \
    node->x.len = x##_len;    \
    memset(node->x.data, 0, x##_len); \
    memcpy(node->x.data, x##_data, x##_len);    

    DATA_SET_ATTR(key);
    DATA_SET_ATTR(value);

#undef DATA_SET_ATTR

    /* add node to list */
    if (type == PARAM_HDR_TYPE) {
        /* hdr set key hash */
        node->key_hash = waf_hash_strlow(mz_hash_str, node->key.data, node->key.len);  
        list_add_tail(&node->list, &data->headers_head);
    }  else if (type == PARAM_VAR_TYPE) {
        /* var set value _hash */
        node->value_hash = waf_hash_strlow(mz_hash_str, node->value.data, node->value.len);  
        list_add_tail(&node->list, &data->vars_head);
    } else {
        return -1;
    }

    return 0;
}

void waf_data_show(void *waf_data)
{
    waf_data_t *data = NULL;
    waf_param_t *param = NULL;

    if (waf_data == NULL) {
        return ;
    }

    data = (waf_data_t *)waf_data;

    //printf("%.*s\n", str_len, str); 

    log_info("method:%d", data->method);
    log_info("uri:%.*s", data->uri.len, data->uri.data);
    log_info("args:%.*s", data->args.len, data->args.data);
    log_info("request_body:%.*s", data->request_body.len, data->request_body.data);

    log_info("\nHeaders:");
    if (!list_empty(&data->headers_head)) {
        list_for_each_entry(param, &data->headers_head, list) {
            log_info("%.*s:%.*s", param->key.len, param->key.data, 
                    param->value.len, param->value.data);
        }
    }

    log_info("\nVars:");
    if (!list_empty(&data->vars_head)) {
        list_for_each_entry(param, &data->vars_head, list) {
            log_info("key: [%.*s] key_hash:[%u]\n: value:[%.*s] value_hash:[%u]", 
                    param->key.len, param->key.data, param->key_hash,
                    param->value.len, param->value.data, param->value_hash);
        }
    }
}

static void waf_param_free(waf_param_t *node)
{
    if(node == NULL) {
        return ;
    }

    if (node->key.data) {
        free(node->key.data);
        node->key.len = 0;
    }

    if (node->value.data) {
        free(node->value.data);
        node->value.len = 0;
    }

    free(node);
}

static void waf_params_free(waf_data_t *data)
{
    waf_param_t *node, *tmp = NULL;

    if (data == NULL) {
        return ;
    }

    if (!list_empty(&data->headers_head)) {
        list_for_each_entry_safe(
                node, tmp, &data->headers_head, list) {
            list_del(&node->list);
            waf_param_free(node);
        }
    }

    if (!list_empty(&data->vars_head)) {
        list_for_each_entry_safe(
                node, tmp,  &data->vars_head, list) {
            list_del(&node->list);
            waf_param_free(node);
        }
    }

    return ;
}

void waf_data_destroy(void *waf_data)
{
    waf_data_t *data = waf_data;

    if (data == NULL) {
        return;
    }
    
    waf_params_free(data);

    free(data);
}


