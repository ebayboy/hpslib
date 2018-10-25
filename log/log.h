#ifndef __LOG_H
#define __LOG_H

#include <stdio.h>
#include <stdarg.h>

typedef void (*log_LockFn)(void *udata, int lock);

enum { LOG_TRACE, LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_FATAL };

#define log_trace(...) log_log(LOG_TRACE, __func__, __LINE__, __VA_ARGS__)
#define log_debug(...) log_log(LOG_DEBUG, __func__, __LINE__, __VA_ARGS__)
#define log_info(...)  log_log(LOG_INFO,  __func__, __LINE__, __VA_ARGS__)
#define log_warn(...)  log_log(LOG_WARN,  __func__, __LINE__, __VA_ARGS__)
#define log_error(...) log_log(LOG_ERROR, __func__, __LINE__, __VA_ARGS__)
#define log_fatal(...) log_log(LOG_FATAL, __func__, __LINE__, __VA_ARGS__)

void log_set_udata(void *udata);
void log_set_lock(log_LockFn fn);

void log_set_fp(FILE *fp);
void log_set_level(int level);
void log_set_quiet(int enable);

void log_log(int level, const char *file, int line, const char *fmt, ...);

#endif
