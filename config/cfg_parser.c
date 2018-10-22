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
#include "cfg_parser.h"

static int cfg_parser_parse_demo(const char *filename)
{
    //用char* 模拟一个JSON字符串
    char* json_string = "{\"test_1\":\"0\", \"test_2\":\"1\", \"test_3\":\"2\"}";

    PR("filename:[%s]\n", filename);

    PR("json_string:[%s]\n", json_string);

    //JSON字符串到cJSON格式
    cJSON* root = cJSON_Parse(json_string); 
    //判断cJSON_Parse函数返回值确定是否打包成功
    if(root == NULL){
        PR("Error: json pack into root error...");
        return -1;
    } else{//打包成功调用cJSON_Print打印输出
        cJSON_Print(root);
    }

    //获取字段值
    //cJSON_GetObjectItem返回的是一个cJSON结构体所以我们可以通过函数返回结构体的方式选择返回类型！
    cJSON * test_1 = cJSON_GetObjectItem(root,"test_1");
    cJSON * test_2 = cJSON_GetObjectItem(root,"test_2");
    cJSON * test_3 = cJSON_GetObjectItem(root,"test_3");

    //打印输出
    if (test_1) {
        PR("test_1:%s\n",test_1->valuestring);
    }
    if (test_2) {
        PR("test_2:%s\n",test_2->valuestring);
    }
    if (test_3) {
        PR("test_3:%s\n",test_3->valuestring);
    }

    //delete root
    cJSON_Delete(root);
}

static int cfg_parser_parse_secrule(cJSON *root)
{
    cJSON *secrule_root, *rules;

    secrule_root = cJSON_GetObjectItem(root, "SecRule");
    if (secrule_root == NULL) {
        return -1;
    }

    int size;
    rules = cJSON_GetObjectItem(secrule_root, "Rules");
    if (rules == NULL) {
        return -1;
    }
    size = cJSON_GetArraySize(rules);

    printf("rule size:%d\n", size);

#if 0
    int i;
    rule_item  = cJSON_GetArrayItem(rules, i);
#endif

    return 0;
}


int cfg_parser_parse2(const char *filename)
{
    PR("filename:%s\n", filename);

    return 0;
}

int cfg_parser_parse(const char *filename)
{
    int rc = 0, ret = 0;
    long flen = 0;
    FILE *fp = NULL;
    char *temp = NULL;
    cJSON *root = NULL, *it = NULL;
    waf_t waf;

    PR("filename:%s\n", filename);

    if (filename == NULL || strlen(filename) == 0) {
        return -1;
    }

    if ((fp = fopen(filename, "r")) == NULL) {
        return -1;
    }

    if ((flen = fsize(fp)) == -1) {
        return -1;
    }

    PR("flen:%d\n", flen);

    if ((temp = (char*)malloc(flen+1)) == NULL) {
        ret = -1;
        goto out;
    }
    memset(temp, 0, sizeof(temp));

    if (fread(temp, flen, 1, fp) != 1) {
        ret = -1;
        goto out;
    }

#ifdef DEBUG
    if ((rc = cfg_parser_parse_demo(filename)) != 0) {
        ret = -1;
        goto out;
    }
#endif

    PR("temp:[%s]\n", temp);

    if ((root = cJSON_Parse(temp)) == NULL) {
        ret = -1;
        goto out;
    }

    memset(&waf, 0, sizeof(waf));

    if ((it = cJSON_GetObjectItem(root,"WafEngine")) != NULL) {
        if (strcasecmp(it->valuestring, "on") == 0) {
            waf.waf_engine = WAF_ENGINE_ON;
        } else {
            waf.waf_engine = WAF_ENGINE_OFF;
        }
    }

    if ((it = cJSON_GetObjectItem(root,"WafAction")) != NULL) {
        if (strcasecmp(it->valuestring, "block") == 0) {
            waf.waf_action = WAF_ACT_BLOCK;
        } else if (strcasecmp(it->valuestring, "log") == 0) {
            waf.waf_action = WAF_ACT_LOG;
        } else if (strcasecmp(it->valuestring, "pass") == 0) {
            waf.waf_action = WAF_ACT_LOG;
        } else {
            waf.waf_action = WAF_ACT_NONE;
        }
    }
 
    if ((it = cJSON_GetObjectItem(root,"WafId")) != NULL) {
        strncpy(waf.waf_id, it->valuestring, sizeof(waf.waf_id) - 1);
    }

    if ((rc = cfg_parser_parse_secrule(root)) != 0) {
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

