#ifndef LOG_H
#define LOG_H
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static const char *event_color = "\x1b[90m";
static const char *error_color = "\x1b[31m";
static const char *info_color = "\x1b[32m";
static const char *fatal_color = "\x1b[35m";

#if defined(LOG_WITH_TIME)
static struct tm *time_event() {
  time_t t = time(NULL);
  struct tm *l = localtime(&t);
  return l;
}

#define log_time()                                                  \
  {                                                                 \
    char buf[64];                                                   \
    struct tm *event_time = time_event();                           \
    buf[strftime(buf, sizeof(buf), "%H:%M:%S", event_time)] = '\0'; \
    printf("%s%s\x1b[0m ", event_color, buf);                       \
  }
#else
#define log_time() \
  {}
#endif // LOG_WITH_TIME

#define log(type, color, format, ...)                                                     \
  {                                                                                       \
    log_time();                                                                           \
    printf("%s%s\x1b[0m %s%s:%d:\x1b[0m ", color, type, event_color, __FILE__, __LINE__); \
    printf(format, ##__VA_ARGS__);                                                        \
    printf("\n");                                                                         \
    fflush(stdout);                                                                       \
  }

#if defined(LOG_DEBUG)
static const char *debug_color = "\x1b[36m";
#define log_debug(format, ...) log("DEBUG", debug_color, format, ##__VA_ARGS__)
#else
#define log_debug(format, ...) \
  {}
#endif // LOG_DEBUG

#define log_info(format, ...) log("INFO ", info_color, format, ##__VA_ARGS__)

#define log_error(format, ...) log("ERROR", error_color, format, ##__VA_ARGS__)

#define log_fatal(format, ...)                        \
  {                                                   \
    log("FATAL", fatal_color, format, ##__VA_ARGS__); \
    exit(-1);                                         \
  }

#endif
