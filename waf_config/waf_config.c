/**
 * @file: waf_config.h
 * @desc:
 *
 * fanpf 2018/10/12
 *
 * Copyright (c) 2018, jd.com.
 * Copyright (c) 2018, jdcloud.com.
 * All rights reserved.
 **/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <cJSON.h>

#include "common.h"
#include "waf_config.h"
#include "log.h"

static int waf_config_init_secrule(cJSON *root, waf_config_t *waf)
{
    cJSON *secrule_root, *rules, *rule, *rule_it;
    int i = 0, size = 0, ret = 0;

    secrule_root = cJSON_GetObjectItem(root, "SecRule");
    if (secrule_root == NULL) {
        return -1;
    }

    rules = cJSON_GetObjectItem(secrule_root, "Rules");
    if (rules == NULL) {
        return -1;
    }
    size = cJSON_GetArraySize(rules);
    printf("rules count:%d\n", size);

#define WAF_RULE_ITEM(x) \
    do  {   \
        if ((rule_it = cJSON_GetObjectItem(rule,#x)) == NULL) {    \
            ret = -1;   \
            goto out;   \
        } \
        strncpy(waf->rules[i].x, rule_it->valuestring, sizeof(waf->rules[i].x) - 1);  \
    } while (0)

#define WAF_RULE_ITEM_INT(x) \
    do  {   \
        if ((rule_it = cJSON_GetObjectItem(rule,#x)) == NULL) {    \
            ret = -1;   \
            goto out;   \
        } \
        if (atoi(rule_it->valuestring) == 0) { \
            return -1;  \
        }   \
        waf->rules[i].x = atoi(rule_it->valuestring);   \
    } while (0)


    for (i = 0; i < size && i < WAF_RULES_MAX; i++) {

        rule  = cJSON_GetArrayItem(rules, i);

        WAF_RULE_ITEM_INT(id);
        WAF_RULE_ITEM(mz);
        WAF_RULE_ITEM(rx);

        waf->idx_cursor++;
    }

out:

#undef WAF_RULE_ITEM
#undef WAF_RULE_ITEM_INT

    log_info("ret:%d\n", ret);
    return ret;
}

int waf_config_init(const char *filename, waf_config_t *waf)
{
    int rc = 0, ret = 0;

    printf("size:%d\n", sizeof(waf_rule_t) * WAF_RULES_MAX);

    long temp_len = 0;
    FILE *fp = NULL;
    char *temp = NULL;
    cJSON *root = NULL, *it = NULL;

    waf->idx_cursor = 0;

    log_info("filename:%s\n", filename);

    if (filename == NULL || strlen(filename) == 0) {
        return -1;
    }

    if ((fp = fopen(filename, "r")) == NULL) {
        return -1;
    }

    if ((temp_len = fsize(fp)) == -1) {
        return -1;
    }

    log_info("temp_len:%d\n", temp_len);
    if ((temp = (char*)malloc(temp_len + 1)) == NULL) {
        ret = -1;
        goto out;
    }
    memset(temp, 0, sizeof(temp));

    if (fread(temp, temp_len, 1, fp) != 1) {
        ret = -1;
        goto out;
    }

    log_info("config :[%s]\n", temp);

    if ((root = cJSON_Parse(temp)) == NULL) {
        ret = -1;
        goto out;
    }

#if 0
    if ((it = cJSON_GetObjectItem(root,"WafEngine")) != NULL) {
        if (strcasecmp(it->valuestring, "on") == 0) {
            waf->waf_engine = WAF_ENGINE_ON;
        } else {
            waf->waf_engine = WAF_ENGINE_OFF;
        }
    }

    if ((it = cJSON_GetObjectItem(root,"WafAction")) != NULL) {
        if (strcasecmp(it->valuestring, "block") == 0) {
            waf->waf_action = WAF_ACT_BLOCK;
        } else if (strcasecmp(it->valuestring, "log") == 0) {
            waf->waf_action = WAF_ACT_LOG;
        } else if (strcasecmp(it->valuestring, "pass") == 0) {
            waf->waf_action = WAF_ACT_LOG;
        } else {
            waf->waf_action = WAF_ACT_NONE;
        }
    }
 
    if ((it = cJSON_GetObjectItem(root,"WafId")) != NULL) {
        strncpy(waf->waf_id, it->valuestring, sizeof(waf->waf_id) - 1);
    }
#endif

    if ((rc = waf_config_init_secrule(root, waf)) != 0) {
        ret = -1;
        goto out;
    }

out:
    if (fp) {
        fclose(fp);
    }

    if (root) {
        cJSON_Delete(root);
    }

    if (temp) {
        free(temp);
    }
    
    return ret;
}

static void waf_config_secrule_show(waf_rule_t *rule)
{
    log_info("rule->id:[%d] mz:[%s] rx:[%s]", 
            rule->id, rule->mz, rule->rx);
}

void waf_config_show(waf_config_t *cfg)
{
    int i;

    if (cfg == NULL) {
        return;
    }

    log_info("waf_engine:%d", cfg->waf_engine);
    log_info("waf_action:%d", cfg->waf_action);
    log_info("waf_id:%s", cfg->waf_id);

    for (i = 0; i< cfg->idx_cursor; i++) {
        waf_config_secrule_show(&cfg->rules[i]);
    }
}



