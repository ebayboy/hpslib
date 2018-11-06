
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

struct passThrough {
    match_t *matcher;
    int *matched_rule_id;
};

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
    str_t cookies;
    str_t request_body;

    list_head_t header_head;
    list_head_t var_head;   /* not used now */
    list_head_t mz_head;    /* user add zone head */
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
    
    if (waf_match_init(&waf->waf_match, &waf->waf_config) == -1) {
        goto error;
    }

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

    rc = waf_match_match(&waf->waf_match, mz->data, mz->len, 0,
            str->data, str->len, matched_rule_id);

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

    if ((buf = malloc(str->len + 1)) == NULL) {
        return SCAN_ERROR;
    }
    memset(buf, 0, str->len + 1);

    dlen = decodeURI(buf, str->len, str->data, str->len);
    rc = waf_match_match(&waf->waf_match, 
            mz->data, mz->len, 0, 
            buf, dlen, matched_rule_id);

    if (buf) {
        free(buf);
    }
    
    return rc;
}

/* eg  $user_agent $http_referer */
static int waf_match_headers_all(waf_data_t *data, int *matched_rule_id)
{
    int rc = 0;
    waf_param_t *hdr = NULL, *var = NULL;
    list_for_each_entry(var, &data->mz_head, list) {
        if (var->key.data == NULL || var->value.data == NULL 
                || var->value.data == 0 || var->value.len == 0) {
            continue;
        }

        if (var->key.len > 2 && strncasecmp(var->key.data, 
                    WAF_MZ_UNESCAPT_PREFIX, 
                    strlen(WAF_MZ_UNESCAPT_PREFIX)) == 0) {
            continue;
        }

        list_for_each_entry(hdr, &data->header_head, list) {
            if (hdr->key.data == NULL || hdr->value.data == NULL 
                    || hdr->key.len == 0 || hdr->value.len == 0) {
                continue;
            }

            if (hdr->key.len != var->value.len) {
                continue;
            }

            if (hdr->key_hash != var->value_hash) {
                continue;
            }

            /* match ori */
            rc = waf_match_ori(&hdr->value, matched_rule_id, &var->key /* mz */);
            if (rc == SCAN_MATCHED) {
                return rc;
            }
        }
    }

    return rc;
}

/* $request_headers */
static int waf_match_request_header(waf_data_t *data, int *matched_rule_id)
{
    int rc = 0;
    waf_param_t *hdr = NULL;
    str_t mz;
   
    mz.data = WAF_MZ_REQUEST_HEADERS;
    mz.len = strlen(WAF_MZ_REQUEST_HEADERS);

    list_for_each_entry(hdr, &data->header_head, list) {
        if (hdr->key.data == NULL || hdr->value.data == NULL 
                || hdr->key.len == 0 || hdr->value.len == 0) {
            continue;
        }

        /* match ori */
        rc = waf_match_ori(&hdr->value, matched_rule_id, &mz);
        if (rc == SCAN_MATCHED) {
            return rc;
        }
    }

    return rc;
}

static int waf_match_unescapted_request_header(waf_data_t *data, int *matched_rule_id)
{
    int rc = 0;
    waf_param_t *hdr = NULL;
    str_t mz;
   
    mz.data = WAF_MZ_U_REQUEST_HEADERS;
    mz.len = strlen(WAF_MZ_U_REQUEST_HEADERS);

    list_for_each_entry(hdr, &data->header_head, list) {
        if (hdr->key.data == NULL || hdr->value.data == NULL 
                || hdr->key.len == 0 || hdr->value.len == 0) {
            continue;
        }

        /* match ori */
        rc = waf_match_unescapted(&hdr->value, matched_rule_id, &mz);
        if (rc == SCAN_MATCHED) {
            return rc;
        }
    }

    return rc;
}

/* eg. $url */
static int waf_match_vars_all(waf_data_t *data, int *matched_rule_id)
{
    int rc = 0;
    waf_param_t *hdr = NULL, *var = NULL;

    list_for_each_entry(var, &data->mz_head, list) {
        if (var->key.data == NULL || var->value.data == NULL 
                || var->value.data == 0 || var->value.len == 0) {
            continue;
        }

        if (var->key.len > 2 && strncasecmp(var->key.data, 
                    WAF_MZ_UNESCAPT_PREFIX, 
                    strlen(WAF_MZ_UNESCAPT_PREFIX)) == 0) {
            continue;
        }

        list_for_each_entry(hdr, &data->var_head, list) {
            if (hdr->key.data == NULL || hdr->value.data == NULL 
                    || hdr->key.len == 0 || hdr->value.len == 0) {
                continue;
            }

            if (hdr->key.len != var->value.len) {
                continue;
            }

            if (hdr->key_hash != var->value_hash) {
                continue;
            }

            /* match ori */
            rc = waf_match_ori(&hdr->value, matched_rule_id, &var->key /* mz */);
            if (rc == SCAN_MATCHED) {
                return rc;
            }
        }
    }

    return rc;
}


static int waf_match_headers_unescapted_all(waf_data_t *data, int *matched_rule_id)
{
    int rc = 0;
    waf_param_t *hdr = NULL, *mz = NULL;
    list_for_each_entry(mz, &data->mz_head, list) {
        if (mz->key.data == NULL || mz->value.data == NULL 
                || mz->value.data == 0 || mz->value.len == 0) {
            continue;
        }
        
        if (mz->key.len <= 2) {
            continue;
        }

        /* u_开头 */
        if (strncasecmp(mz->key.data, 
                    WAF_MZ_UNESCAPT_PREFIX, 
                    strlen(WAF_MZ_UNESCAPT_PREFIX)) != 0) {
            continue;
        }

        list_for_each_entry(hdr, &data->header_head, list) {
            if (hdr->key.data == NULL || hdr->value.data == NULL 
                    || hdr->key.len == 0 || hdr->value.len == 0) {
                continue;
            }

            if (hdr->key.len != mz->value.len) {
                continue;
            }

            if (hdr->key_hash != mz->value_hash) {
                continue;
            }

            rc = waf_match_unescapted(&hdr->value, matched_rule_id, &mz->key /* mz */);
            if (rc == SCAN_MATCHED) {
                return rc;
            }
        }
    }

    return rc;
}

static int waf_match_vars_unescapted_all(waf_data_t *data, int *matched_rule_id)
{
    int rc = 0;
    waf_param_t *hdr = NULL, *var = NULL;
    list_for_each_entry(var, &data->mz_head, list) {
        if (var->key.data == NULL || var->value.data == NULL 
                || var->value.data == 0 || var->value.len == 0) {
            continue;
        }
        
        if (var->key.len <= 2) {
            continue;
        }

        /* u_开头 */
        if (strncasecmp(var->key.data, 
                    WAF_MZ_UNESCAPT_PREFIX, 
                    strlen(WAF_MZ_UNESCAPT_PREFIX)) != 0) {
            continue;
        }

        list_for_each_entry(hdr, &data->var_head, list) {
            if (hdr->key.data == NULL || hdr->value.data == NULL 
                    || hdr->key.len == 0 || hdr->value.len == 0) {
                continue;
            }

            if (hdr->key.len != var->value.len) {
                continue;
            }

            if (hdr->key_hash != var->value_hash) {
                continue;
            }

            rc = waf_match_unescapted(&hdr->value, matched_rule_id, &var->key /* mz */);
            if (rc == SCAN_MATCHED) {
                return rc;
            }
        }
    }

    return rc;
}


/* $uri $args $request_body */
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

    /* match cookies */
    if (data->cookies.data && data->cookies.len > 0) {
        mz.data = WAF_MZ_HTTP_COOKIE;
        mz.len = strlen(WAF_MZ_HTTP_COOKIE);
        rc = waf_match_ori(&data->cookies, matched_rule_id, &mz);
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

static int ngx_http_waf_match_handler (
        int type,
        char *dec_out,
        int dec_out_len,
        void *passThrough)
{
    int ret = 0, i;
    struct passThrough *pt = (struct passThrough *)passThrough;
    match_t *matcher = pt->matcher;

    if (passThrough == NULL 
            || dec_out == NULL
            || dec_out_len <= 0
            || dec_out_len > DECOUT_SIZE_MAX ) {
        return -1;
    }


    for (i = 0; i < DECODE_TYPE_SIZE; i++) {
        if (matcher->decode_type[i] == type) {
            if ((ret += match_match(matcher, dec_out, 
                    dec_out_len, pt->matched_rule_id)) == SCAN_MATCHED) {
                return ret;
            }
        }
    }

    return ret;
}

static int waf_match_decode_get_args(match_t *matcher, waf_data_t *data, void *pt)
{
    int ret = 0;
    int do_unbase64 = 1, do_unescaped = 1, do_gbk2utf8 = 1;

    ret += url_decode(
            data->args.data,
            data->args.len,
            ngx_http_waf_match_handler, 
            pt,
            matcher->do_decode, /* do_unbase64, */
            matcher->do_decode, /* do_unescaped, */
            matcher->do_decode); /* do_gbk2utf8); */

    return ret;
}

static int waf_match_decode_cookies(match_t *matcher, waf_data_t *data, void *pt)
{
    int ret = 0;

    ret += cookie_decode(
            NULL,
            data->cookies.data,
            data->cookies.len,
            ngx_http_waf_match_handler, 
            pt,
            matcher->do_decode, /* do_unbase64, */
            matcher->do_decode, /* do_unescaped, */
            matcher->do_decode); /* do_gbk2utf8); */

    return ret;
}

static int waf_match_decode_body(match_t *matcher, waf_data_t *data, void *pt)
{
    int ret = 0, content_type = DATA_TYPE_UNKNOWN;

    ret += ngx_http_waf_data_decode(
            data->request_body.data,
            data->request_body.len,
            ngx_http_waf_match_handler, 
            pt, 
            &content_type, /* content_type,  */
            matcher->do_decode, /* do_unbase64, */
            matcher->do_decode, /* do_unescaped, */
            matcher->do_decode); /* do_gbk2utf8); */

    return ret;
}

/* 自适应解码  */
/* $u_get_key $args_key $file_content */
static int waf_match_decode_all( waf_data_t *data, 
        int *matched_rule_id, waf_t *waf) 
{
    int ret = 0, i;
    match_t *matcher = NULL;
    waf_match_t *waf_matcher = &waf->waf_match;
    struct passThrough pt;

    for (i = 0 ; i < waf_matcher->matcher_cursor; i++ ) { 
        if ((matcher = waf_matcher->matchers[i]) == NULL) {
            continue;
        }   

        if (!matcher->do_parse) {
            continue;
        }

        memset(&pt, 0, sizeof(pt));
        pt.matcher = matcher;
        pt.matched_rule_id = matched_rule_id;

        /* args decode */
        if ((ret = waf_match_decode_get_args(matcher, data, &pt)) > 0) {
            return SCAN_MATCHED;
        }

        /* cookie decode */
        if ((ret = waf_match_decode_cookies(matcher, data, &pt)) > 0) {
            return SCAN_MATCHED;
        }

        /* body decode */
        if ((ret = waf_match_decode_body(matcher, data, &pt)) > 0) {
            return SCAN_MATCHED;
        }
    }   

    return ret;
}

static int waf_match_unescapted_all(waf_data_t *data, int *matched_rule_id)
{
    int rc = 0;
    str_t mz;

    /* uri */
    if (data->uri.data && data->uri.len > 0) {
        mz.data = WAF_MZ_U_URI;
        mz.len = strlen(WAF_MZ_U_URI);
        rc = waf_match_unescapted(&data->uri, matched_rule_id, &mz);
        if (rc == SCAN_MATCHED) {
            return rc;
        }
    }

    /* args */
    if (data->args.data && data->args.len > 0) {
        mz.data = WAF_MZ_U_ARGS;
        mz.len = strlen(WAF_MZ_U_ARGS);
        rc = waf_match_unescapted(&data->args, matched_rule_id, &mz);
        if (rc == SCAN_MATCHED) {
            return rc;
        }
    }

    /* cookies */
    if (data->cookies.data && data->cookies.len > 0) {
        mz.data = WAF_MZ_U_HTTP_COOKIE;
        mz.len = strlen(WAF_MZ_U_HTTP_COOKIE);
        rc = waf_match_unescapted(&data->cookies, matched_rule_id, &mz);
        if (rc == SCAN_MATCHED) {
            return rc;
        }
    }

    /* body */
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
    if ((rc = waf_match_vars_all(data, matched_rule_id)) == SCAN_MATCHED) {
        return rc;
    }
    if ((rc = waf_match_ori_all(data, matched_rule_id)) == SCAN_MATCHED) {
        return rc;
    }
    if ((rc = waf_match_request_header(data, matched_rule_id)) == SCAN_MATCHED) {
        return rc;
    }

    /* escapted */
    if ((rc = waf_match_headers_unescapted_all(data, matched_rule_id)) == SCAN_MATCHED) {
        return rc;
    }
    if ((rc = waf_match_vars_unescapted_all(data, matched_rule_id)) == SCAN_MATCHED) {
        return rc;
    }
    if ((rc = waf_match_unescapted_all(data, matched_rule_id)) == SCAN_MATCHED) {
        return rc;
    }
    if ((rc = waf_match_unescapted_request_header(data, matched_rule_id)) == SCAN_MATCHED) {
        return rc;
    }

    /* decode */
    if ((rc = waf_match_decode_all(data, matched_rule_id, waf)) == SCAN_MATCHED) {
        return rc;
    }

    return SCAN_NOT_MATCHED;
}

void * waf_data_create(
        http_method_e method, 
        unsigned char  *uri, size_t uri_len,
        unsigned char *args, size_t args_len,
        unsigned char *cookies, size_t cookies_len,
        unsigned char *request_body, size_t req_len)
{
    waf_data_t *data;

    if((data = malloc(sizeof(waf_data_t))) == NULL) {
        return NULL;
    }
    memset(data, 0, sizeof(waf_data_t));

    INIT_LIST_HEAD(&data->header_head);
    INIT_LIST_HEAD(&data->mz_head);
    INIT_LIST_HEAD(&data->var_head);

    data->method = method;

    data->uri.data = uri;
    data->uri.len = uri_len;

    data->args.data = args;
    data->args.len = args_len;

    data->cookies.data = cookies;
    data->cookies.len = cookies_len;

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
    unsigned char mz_hash_str[WAF_RULE_MZ_LEN] = {0};

    if (data == NULL || key_data == NULL || key_len ==0
            || value_data == NULL || value_len == 0) {
        return -1;
    }

    if (type != PARAM_HDR_TYPE 
            && type != PARAM_MZ_TYPE
            && type != PARAM_VAR_TYPE) {
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
    node->x.data = malloc(x##_len + 1);   \
    if (node->x.data == NULL) { \
        free(node); \
        return -1;  \
    }       \
    memset(node->x.data, 0, x##_len + 1); \
    node->x.len = x##_len;    \
    fprintf(stderr, "x.len: %d", node->x.len);    \
    memcpy(node->x.data, x##_data, x##_len);    

    DATA_SET_ATTR(key);
    DATA_SET_ATTR(value);

#undef DATA_SET_ATTR

    /* add node to list */
    if (type == PARAM_HDR_TYPE) {
        /* hdr set key hash */
        node->key_hash = waf_hash_strlow(mz_hash_str, node->key.data, node->key.len);  
        node->value_hash = waf_hash_strlow(mz_hash_str, node->value.data, node->value.len);  
        list_add_tail(&node->list, &data->header_head);
    }  else if (type == PARAM_MZ_TYPE) {
        /* var set value _hash */
        node->key_hash = waf_hash_strlow(mz_hash_str, node->key.data, node->key.len);  
        node->value_hash = waf_hash_strlow(mz_hash_str, node->value.data, node->value.len);  
        list_add_tail(&node->list, &data->mz_head);
    } else if (type == PARAM_VAR_TYPE) {
        /* var set value _hash */
        node->key_hash = waf_hash_strlow(mz_hash_str, node->key.data, node->key.len);  
        node->value_hash = waf_hash_strlow(mz_hash_str, node->value.data, node->value.len);  
        list_add_tail(&node->list, &data->var_head);
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
    log_info("cookies:%.*s", data->cookies.len, data->cookies.data);
    log_info("request_body:%.*s", data->request_body.len, data->request_body.data);

    log_info("\nHeaders:");
    if (!list_empty(&data->header_head)) {
        list_for_each_entry(param, &data->header_head, list) {
            log_info("%.*s:%.*s", param->key.len, param->key.data, 
                    param->value.len, param->value.data);
        }
    }

    log_info("\nVars:");
    if (!list_empty(&data->var_head)) {
        list_for_each_entry(param, &data->var_head, list) {
            log_info("%.*s:%.*s", param->key.len, param->key.data, 
                    param->value.len, param->value.data);
        }
    }

    log_info("\nMZS:");
    if (!list_empty(&data->mz_head)) {
        list_for_each_entry(param, &data->mz_head, list) {
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

    if (!list_empty(&data->header_head)) {
        list_for_each_entry_safe(
                node, tmp, &data->header_head, list) {
            list_del(&node->list);
            waf_param_free(node);
        }
    }

    if (!list_empty(&data->var_head)) {
        list_for_each_entry_safe(
                node, tmp, &data->var_head, list) {
            list_del(&node->list);
            waf_param_free(node);
        }
    }

    if (!list_empty(&data->mz_head)) {
        list_for_each_entry_safe(
                node, tmp,  &data->mz_head, list) {
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


