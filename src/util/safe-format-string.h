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

#include "config.h"

#ifndef __SAFE_FORMAT_STRING_H__
#define __SAFE_FORMAT_STRING_H__

#include <stdlib.h>

/*
 * This is a neutered printf variant that can be used with user-provided
 * format strings.
 *
 * Not only are the normal printf functions not safe to use on user-provided
 * input (ie: can crash, be abused, etc), they're also very brittle with
 * regards to positional arguments: one must consume them all or printf will
 * just abort(). This is because arguments of different sizes are accepted
 * in the varargs. So obviously the positional code cannot know the offset
 * of the relevant varargs if some are not consumed (ie: tagged with a
 * field type).
 *
 * Thus the only accepted field type here is 's'. It's all we need.
 *
 * In general new code should use a better syntax than printf format strings
 * for configuration options. This code is here to facilitate robust processing
 * of the full_name_format syntax we already have, which has been documented as
 * "printf(3) compatible".
 *
 * Features:
 * - Only string 's' fields are supported
 * - All the varargs should be strings, followed by a NULL argument
 * - Both positional '%$1s' and non-positional '%s' are supported
 * - Field widths '%8s' work as expected
 * - Precision '%.8s' works, but precision cannot be read from a field
 * - Left alignment flag is supported '%-8s'.
 * - The space flag '% 8s' has no effect (it's the default for string fields).
 * - No more than six digits are supported for widths, precisions, etc.
 * - Percent signs are to be escaped as usual '%%'
 *
 * Use of other flags or field types will cause the relevant printf call to
 * return -1. Using too many arguments or incorrect positional arguments
 * will also cause the call to fail.
 *
 * Functions return -1 on failure and set errno. Otherwise they return
 * the full length of the string that would be formatted, with the same
 * semantics as snprintf().
 */

#ifndef GNUC_NULL_TERMINATED
#if __GNUC__ >= 4
#define GNUC_NULL_TERMINATED __attribute__((__sentinel__))
#else
#define GNUC_NULL_TERMINATED
#endif
#endif

int        safe_format_string    (char *str,
                                  size_t len,
                                  const char *format,
                                  ...) GNUC_NULL_TERMINATED;

int        safe_format_string_cb (void (* callback) (void *data, const char *piece, size_t len),
                                  void *data,
                                  const char *format,
                                  const char * const args[],
                                  int num_args);

#endif /* __SAFE_FORMAT_STRING_H__ */
