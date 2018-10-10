
/**
 * @file: base64.h
 * @desc:
 *
 * Pengfei.Fan,  2018/05/10
 *
 * Copyright (c) 2018, jd.com.
 * Copyright (c) 2018, jdcloud.com.
 * All rights reserved.
 **/
#ifndef __BASE64_H__
#define __BASE64_H__

/* RETURN: success-outlen; failed:-1 ;  */
int base64_encode(const unsigned char *in, unsigned int inlen, char *out);

/* RETURN: success-outlen; failed:-1 ;  */
int base64_decode(const char *in, unsigned int inlen, unsigned char *out);

int base64_check_is_base64_encode(const char *in, unsigned int inlen);

int base64_result_is_valid(unsigned char *ret, int retlen);

#endif /* __BASE64_H__ */

