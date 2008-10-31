#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

int debug_level = 3;

void debug_fn(const char *format, ...)
{
    va_list ap;
    char *s = NULL;

    va_start(ap, format);
    vasprintf(&s, format, ap);
    va_end(ap);

    /*write(state.fd, s, strlen(s));*/
    fprintf(stderr, s);
    free(s);
}
