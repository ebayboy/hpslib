
/**
 * @file: base64.c
 * @desc:
 *
 * Pengfei.Fan,  2018/05/10
 *
 * Copyright (c) 2018, jd.com.
 * Copyright (c) 2018, jdcloud.com.
 * All rights reserved.
 **/


#include <stdio.h>

#include "base64.h"

/* BASE 64 encode table */
static const char base64en[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/',
};

#define BASE64_PAD	'='


#define BASE64DE_FIRST	'+'
#define BASE64DE_LAST	'z'
/* ASCII order for BASE 64 decode, -1 in unused character */
static const signed char base64de[] = {
    /* '+', ',', '-', '.', '/', '0', '1', '2', */ 
    62,  -1,  -1,  -1,  63,  52,  53,  54,

    /* '3', '4', '5', '6', '7', '8', '9', ':', */
    55,  56,  57,  58,  59,  60,  61,  -1,

    /* ';', '<', '=', '>', '?', '@', 'A', 'B', */
    -1,  -1,  -1,  -1,  -1,  -1,   0,   1, 

    /* 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', */
    2,   3,   4,   5,   6,   7,   8,   9,

    /* 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', */ 
    10,  11,  12,  13,  14,  15,  16,  17,

    /* 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', */
    18,  19,  20,  21,  22,  23,  24,  25,

    /* '[', '\', ']', '^', '_', '`', 'a', 'b', */ 
    -1,  -1,  -1,  -1,  -1,  -1,  26,  27,

    /* 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', */ 
    28,  29,  30,  31,  32,  33,  34,  35,

    /* 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', */
    36,  37,  38,  39,  40,  41,  42,  43,

    /* 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', */
    44,  45,  46,  47,  48,  49,  50,  51,
};

/* RETURN: 0-not base64;  1-base64 */
int base64_check_is_base64_encode(const char *in, unsigned int inlen)
{
    unsigned int i = 0;

#if 0
    if (inlen % 4 != 0) {
        return 0;
    }
#endif

    for (i = 0; i<inlen; i++) {
        if (in[i] >='A' && in[i] <='Z') {
            continue;

        }
        if (in[i] >='a' && in[i] <='z') {
            continue;
        }
        if (in[i] >='0' && in[i] <='9') {
            continue;
        }
        if (in[i] == '+' || in[i] == '/') {
            continue;
        }

        /* =必须出现在最后两位， 且如果等号出现在倒数到一位， 则最后一位也必须是= */
        if (in[i] == '=') {
            if ((i >= inlen -2)) {
                /* 等号必须出现在最后两位 */

                if (i == inlen - 2) {
                    /* 如果等号出现在倒数第二位 */

                    if (in[inlen-1] == '=') {
                        /* 倒数第一位也必须是= */
                        continue;
                    }
                } else {
                    /* 如果等号出现在倒数第一位 */
                    continue;

                }
            }
        }

        /* not base64 byte */
        return 0;
    }

    /* is base64 bytes */
    return 1;
}


int base64_encode(const unsigned char *in, unsigned int inlen, char *out)
{
    unsigned int i, j;

    for (i = j = 0; i < inlen; i++) {
        int s = i % 3; 			/* from 6/gcd(6, 8) */

        switch (s) {
            case 0:
                out[j++] = base64en[(in[i] >> 2) & 0x3F];
                continue;
            case 1:
                out[j++] = base64en[((in[i-1] & 0x3) << 4) + ((in[i] >> 4) & 0xF)];
                continue;
            case 2:
                out[j++] = base64en[((in[i-1] & 0xF) << 2) + ((in[i] >> 6) & 0x3)];
                out[j++] = base64en[in[i] & 0x3F];
        }
    }

    /* move back */
    i -= 1;

    /* check the last and add padding */
    if ((i % 3) == 0) {
        out[j++] = base64en[(in[i] & 0x3) << 4];
        out[j++] = BASE64_PAD;
        out[j++] = BASE64_PAD;
    } else if ((i % 3) == 1) {
        out[j++] = base64en[(in[i] & 0xF) << 2];
        out[j++] = BASE64_PAD;
    }

    return j;
}

/* 
FUNCTION: 对base64解码后的结果进行校验， 
ASCI码在0~127范围内则认为有效， 否则无效
RETURN: 1-valied; 0-invalid */
int base64_result_is_valid(unsigned char *ret, int retlen) 
{
    int i, pos;

    for(i = 0; i< retlen; i++) {
        pos = ret[i];
        if (pos < 0 || pos > 127) {
            return 0;
        }
    }

    return 1;
}

int base64_decode(const char *in, unsigned int inlen, unsigned char *out)
{
    unsigned int i, j;

    if (!base64_check_is_base64_encode(in, inlen)) {
        return -1;
    }

    for (i = j = 0; i < inlen; i++) {
        int c;
        int s = i % 4; 			/* from 8/gcd(6, 8) */

        if (in[i] == '=') {
            goto check_result;
        }

        if (in[i] < BASE64DE_FIRST || in[i] > BASE64DE_LAST ||
                (c = base64de[in[i] - BASE64DE_FIRST]) == -1)
            return -1;

        switch (s) {
            case 0:
                out[j] = ((unsigned int)c << 2) & 0xFF;
                continue;
            case 1:
                out[j++] += ((unsigned int)c >> 4) & 0x3;

                /* if not last char with padding */
                if (i < (inlen - 3) || in[inlen - 2] != '=')
                    out[j] = ((unsigned int)c & 0xF) << 4; 
                continue;
            case 2:
                out[j++] += ((unsigned int)c >> 2) & 0xF;

                /* if not last char with padding */
                if (i < (inlen - 2) || in[inlen - 1] != '=')
                    out[j] =  ((unsigned int)c & 0x3) << 6;
                continue;
            case 3:
                out[j++] += (unsigned char)c;
        }
    }

check_result:
    if (base64_result_is_valid(out, j) == 0) {
        /* base64 解码无效 */
        return -1;
    }

    return j;
}

