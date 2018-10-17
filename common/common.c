
/**
 * author: fanpf
 * date : 2018/10/12
 * desc : common module
 **/

#include <stdio.h>

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
