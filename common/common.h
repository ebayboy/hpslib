

#ifndef __COMMON_H__
#define __COMMON_H__

#define WAF_RULES_MAX       4096
#define WAF_ID_LEN          128
#define WAF_MZ_MAX          128

#define WAF_RULE_ID_LEN     128
#define WAF_RULE_MZ_LEN     128
#define WAF_RULE_MZS_LEN    1024
#define WAF_RULE_RX_LEN     4096

#define waf_tolower(c)      (unsigned char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define waf_toupper(c)      (unsigned char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)
#define waf_hash(key, c)   ((unsigned int) key * 31 + c)

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

#endif
