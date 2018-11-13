
/**
 * author: fanpf
 * date : 2018/10/12
 * desc : common module
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

long fsize(FILE *fp)
{
    long n;
    fpos_t fpos; 
    fgetpos(fp, &fpos); 
    fseek(fp, 0, SEEK_END);
    n = ftell(fp);
    fsetpos(fp,&fpos); 

    return n;
}

void strim(char *str)
{
    char *copied, *tail = NULL;

    if ( str == NULL ) { 
        return;
    }   

    for( copied = str; *str; str++ ) { 
        if ( *str != ' ' && *str != '\t' ) { 
            *copied++ = *str;
            tail = copied;    
        }   
        else {
            if ( tail )
                *copied++ = *str;
        }   
    }   

    if ( tail ) { 
        *tail = 0;
    } else {
        *copied = 0;
    }   

    return;
}

unsigned int waf_hash_strlow(
        unsigned char *dst, 
        const unsigned char *src, 
        size_t n)
{
    unsigned int key;

    key = 0;

    while (n--) {
        *dst = waf_tolower(*src);
        key = waf_hash(key, *dst);
        dst++;
        src++;
    }

    return key;
}

int fread_file(const char *filename, unsigned char **buf, int *buflen)
{
    FILE *fp = NULL;
    unsigned char *temp = NULL;
    size_t fsize = 0;
    fpos_t fpos; 

    if (filename == NULL || buf == NULL  || buflen == NULL) {
        return -1;
    }

    if ((fp = fopen(filename, "r")) == NULL) {
        return -1;
    }

    fgetpos(fp, &fpos); 
    fseek(fp, 0, SEEK_END);
    if ((fsize = ftell(fp)) == -1) {
        fclose(fp);
        return -1;
    }
    fsetpos(fp,&fpos); 

    if ((temp = (char*)malloc(fsize + 1)) == NULL) {
        fclose(fp);
        return -1;
    }
    memset(temp, 0, sizeof(temp));

    if (fread(temp, fsize, 1, fp) != 1) {
        fclose(fp);
        return -1;
    }

    *buf = temp;
    *buflen = fsize;

    fclose(fp);

    return 0;
}
