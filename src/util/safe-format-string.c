/*
 * This file originated in the realmd project
 *
 * Copyright 2013 Red Hat Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 *
 * Author: Stef Walter <stefw@redhat.com>
 */

/*
 * Some snippets of code from gnulib, but have since been refactored
 * to within an inch of their life...
 *
 * vsprintf with automatic memory allocation.
 * Copyright (C) 1999, 2002-2003 Free Software Foundation, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published
 * by the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 */

#include "config.h"

#include "safe-format-string.h"

#include <errno.h>
#include <stdarg.h>
#include <string.h>

#ifndef MIN
#define MIN(a, b)  (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b)  (((a) > (b)) ? (a) : (b))
#endif

static void
safe_padding (int count,
              int *total,
              void (* copy_fn) (void *, const char *, size_t),
              void *data)
{
    char eight[] = "        ";
    int num;

    while (count > 0) {
        num = MIN (count, 8);
        copy_fn (data, eight, num);
        count -= num;
        *total += num;
    }
}

static void
dummy_copy_fn (void *data,
               const char *piece,
               size_t len)
{

}

int
safe_format_string_cb (void (* copy_fn) (void *, const char *, size_t),
                       void *data,
                       const char *format,
                       const char * const args[],
                       int num_args)
{
    int at_arg = 0;
    const char *cp;
    int precision;
    int width;
    int len;
    const char *value;
    int total;
    int left;
    int i;

    if (!copy_fn)
        copy_fn = dummy_copy_fn;

    total = 0;
    cp = format;

    while (*cp) {

        /* Piece of raw string */
        if (*cp != '%') {
            len = strcspn (cp, "%");
            copy_fn (data, cp, len);
            total += len;
            cp += len;
            continue;
        }

        cp++;

        /* An literal percent sign? */
        if (*cp == '%') {
            copy_fn (data, "%", 1);
            total++;
            cp++;
            continue;
        }

        value = NULL;
        left = 0;
        precision = -1;
        width = -1;

        /* Test for positional argument.  */
        if (*cp >= '0' && *cp <= '9') {
            /* Look-ahead parsing, otherwise skipped */
            if (cp[strspn (cp, "0123456789")] == '$') {
                unsigned int n = 0;
                for (i = 0; i < 6 && *cp >= '0' && *cp <= '9'; i++, cp++) {
                    n = 10 * n + (*cp - '0');
                }
                /* Positional argument 0 is invalid. */
                if (n == 0) {
                    errno = EINVAL;
                    return -1;
                }
                /* Positional argument N too high */
                if (n > num_args) {
                    errno = EINVAL;
                    return -1;
                }
                value = args[n - 1];
                cp++; /* $ */
            }
        }

        /* Read the supported flags. */
        for (; ; cp++) {
            if (*cp == '-')
                left = 1;
            /* Supported but ignored */
            else if (*cp != ' ')
                break;
        }

        /* Parse the width. */
        if (*cp >= '0' && *cp <= '9') {
            width = 0;
            for (i = 0; i < 6 && *cp >= '0' && *cp <= '9'; i++, cp++) {
                width = 10 * width + (*cp - '0');
            }
        }

        /* Parse the precision. */
        if (*cp == '.') {
            precision = 0;
            for (i = 0, cp++; i < 6 && *cp >= '0' && *cp <= '9'; cp++, i++) {
                precision = 10 * precision + (*cp - '0');
            }
        }

        /* Read the conversion character.  */
        switch (*cp++) {
        case 's':
            /* Non-positional argument */
            if (value == NULL) {
                /* Too many arguments used */
                if (at_arg == num_args) {
                    errno = EINVAL;
                    return -1;
                }
                value = args[at_arg++];
            }
            break;

        /* No other conversion characters are supported */
        default:
            errno = EINVAL;
            return -1;
        }

        /* How many characters are we printing? */
        len = strlen (value);
        if (precision >= 0)
            len = MIN (precision, len);

        /* Do we need padding? */
        safe_padding (left ? 0 : width - len, &total, copy_fn, data);

        /* The actual data */;
        copy_fn (data, value, len);
        total += len;

        /* Do we need padding? */
        safe_padding (left ? width - len : 0, &total, copy_fn, data);
    }

    return total;
}

static const char **
valist_to_args (va_list va,
                int *num_args)
{
    int alo_args;
    const char **args;
    const char *arg;
    void *mem;

    *num_args = alo_args = 0;
    args = NULL;

    for (;;) {
        arg = va_arg (va, const char *);
        if (arg == NULL)
            break;
        if (*num_args == alo_args) {
            alo_args += 8;
            mem = realloc (args, sizeof (const char *) * alo_args);
            if (!mem) {
                free (args);
                return NULL;
            }
            args = mem;
        }
        args[(*num_args)++] = arg;
    }

    return args;
}

struct sprintf_ctx {
    char *data;
    size_t length;
    size_t alloc;
};

static void
snprintf_copy_fn (void *data,
                  const char *piece,
                  size_t length)
{
    struct sprintf_ctx *cx = data;

    /* Don't copy if too much data */
    if (cx->length > cx->alloc)
        length = 0;
    else if (cx->length + length > cx->alloc)
        length = cx->alloc - cx->length;

    if (length > 0)
        memcpy (cx->data + cx->length, piece, length);

    /* Null termination happens later */
    cx->length += length;
}

int
safe_format_string (char *str,
                    size_t len,
                    const char *format,
                    ...)
{
    struct sprintf_ctx cx;
    int num_args;
    va_list va;
    const char **args;
    int error = 0;
    int ret;

    cx.data = str;
    cx.length = 0;
    cx.alloc = len;

    va_start (va, format);
    args = valist_to_args (va, &num_args);
    va_end (va);

    if (args == NULL) {
        errno = ENOMEM;
        return -1;
    }

    if (len)
        cx.data[0] = '\0';

    ret = safe_format_string_cb (snprintf_copy_fn, &cx, format, args, num_args);
    if (ret < 0) {
        error = errno;
    } else if (len > 0) {
        cx.data[MIN (cx.length, len - 1)] = '\0';
    }

    free (args);

    if (error)
        errno = error;
    return ret;
}
