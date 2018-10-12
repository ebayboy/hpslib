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

#include <cJSON.h>

#include "common.h"

static int cfg_parser_parse_demo()
{
    //用char* 模拟一个JSON字符串
    char* json_string = "{\"test_1\":\"0\", \"test_2\":\"1\", \"test_3\":\"2\"}";

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

static int cfg_parser_parse_secrule()
{

    return 0;
}

int cfg_parser_parse(const char *filename)
{
    int rc = 0;
    long flen;
    FILE *fp;

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

#ifdef DEBUG
    if ((rc = cfg_parser_parse_demo()) != 0) {
        return rc;
    }
#endif

    if ((rc = cfg_parser_parse_secrule()) != 0) {
        return rc;
    }
    
    return 0;
}

