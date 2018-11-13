

#ifndef __COMMON_H__
#define __COMMON_H__

#define WAF_RULES_MAX       4096
#define WAF_ID_LEN          128
#define WAF_MZ_MAX          4096

#define WAF_RULE_ID_LEN     128
#define WAF_RULE_MZ_LEN     128
#define WAF_RULE_MZS_LEN    1024
#define WAF_RULE_RX_LEN     4096

#define DECODE_TYPE_SIZE                16
#define DECOUT_SIZE_MAX                 104857600

#define waf_tolower(c)      (unsigned char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define waf_toupper(c)      (unsigned char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)
#define waf_hash(key, c)   ((unsigned int) key * 31 + c)

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
#define WAF_MZ_HTTP_URL             "$url"  /* var */
#define WAF_MZ_REQUEST_URI          "$request_uri"
#define WAF_MZ_REQUEST_BODY         "$request_body"
#define WAF_MZ_HTTP_REFERER         "$http_referer"
#define WAF_MZ_HTTP_USER_AGENT      "$http_user_agent"

#define WAF_MZ_HTTP_COOKIE          "$http_cookie"
#define WAF_MZ_REQUEST_HEADERS      "$request_headers"

/* html decode */
#define WAF_MZ_U_URI                "$u_uri"
#define WAF_MZ_U_ARGS               "$u_args"
#define WAF_MZ_U_REQUEST_URI        "$u_request_uri"
#define WAF_MZ_U_REQUEST_BODY       "$u_request_body"
#define WAF_MZ_U_HTTP_REFERER       "$u_http_referer"
#define WAF_MZ_U_HTTP_USER_AGENT    "$u_http_user_agent"
#define WAF_MZ_U_HTTP_URL           "$u_url"
#define WAF_MZ_U_HTTP_COOKIE        "$u_http_cookie"
#define WAF_MZ_U_REQUEST_HEADERS    "$u_request_headers"

#define WAF_MZ_UNESCAPT_PREFIX      "$u_"

/* define decode */
#define WAF_MZ_U_GET_KEY            "$u_get_key"
#define WAF_MZ_U_GET_VALUE          "$u_get_value"
#define WAF_MZ_U_COOKIE_KEY         "$u_cookie_key"
#define WAF_MZ_U_COOKIE_VALUE       "$u_cookie_value"
#define WAF_MZ_ARGS_KEY             "$args_key"
#define WAF_MZ_ARGS_VALUE           "$args_value"
#define WAF_MZ_U_ARGS_KEY           "$u_args_key"
#define WAF_MZ_U_ARGS_VALUE         "$u_args_value"
#define WAF_MZ_U_POST_KEY           "$u_post_key"
#define WAF_MZ_U_POST_VALUE         "$u_post_value"
#define WAF_MZ_FILE_NAME            "$file_name"
#define WAF_MZ_FILE_CONTENT         "$file_content"

#if 0
typedef enum {
#if 0
    MZ_TYPE_URI,
    MZ_TYPE_ARGS,
    MZ_TYPE_HTTP_URL,
    MZ_TYPE_REQUEST_URI,
    MZ_TYPE_REQUEST_BODY,
    MZ_TYPE_HTTP_REFERER,
    MZ_TYPE_HTTP_USER_AGENT,

    MZ_TYPE_HTTP_COOKIE,
    MZ_TYPE_REQUEST_HEADERS,

/* html decode */
    MZ_TYPE_U_URI,
    MZ_TYPE_U_ARGS,
    MZ_TYPE_U_REQUEST_URI,
    MZ_TYPE_U_REQUEST_BODY,
    MZ_TYPE_U_HTTP_REFERER,
    MZ_TYPE_U_HTTP_USER_AGENT,
    MZ_TYPE_U_HTTP_URL,
    MZ_TYPE_U_HTTP_COOKIE,
    MZ_TYPE_U_REQUEST_HEADERS,

#endif
/* define decode */
    MZ_TYPE_U_GET_KEY,
    MZ_TYPE_U_GET_VALUE,
    MZ_TYPE_U_COOKIE_KEY,
    MZ_TYPE_U_COOKIE_VALUE,
    MZ_TYPE_ARGS_KEY, 
    MZ_TYPE_ARGS_VALUE,
    MZ_TYPE_U_ARGS_KEY,
    MZ_TYPE_U_ARGS_VALUE,
    MZ_TYPE_U_POST_KEY,
    MZ_TYPE_U_POST_VALUE,
    MZ_TYPE_FILE_NAME,
    MZ_TYPE_FILE_CONTENT,

    MZ_TYPE_MAX /* max */
} waf_mz_type_e;
#endif


typedef enum {
    WAF_ENGINE_OFF = 0, 
    WAF_ENGINE_ON = 1
} waf_engine_e;

typedef enum {
    WAF_ACT_NONE = 0,
    WAF_ACT_LOG,
    WAF_ACT_PASS,
    WAF_ACT_BLOCK,
    WAF_ACT_MAX
} waf_action_e;

long fsize(FILE *fp);

void strim(char *str);

unsigned int waf_hash_strlow(
        unsigned char *dst, 
        const unsigned char *src, 
        size_t n);

/**
 * @buflen - out
 * @buf - out
 * @filename - in 
 **/
int fread_file(const char *filename, 
        unsigned char **buf, int *buflen);

#endif


