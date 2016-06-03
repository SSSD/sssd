/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2014 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef SSS_SIFP_PRIVATE_H_
#define SSS_SIFP_PRIVATE_H_

#include <dbus/dbus.h>
#include "lib/sifp/sss_sifp.h"

void *sss_sifp_alloc_zero(sss_sifp_ctx *ctx, size_t size, size_t num);

#define _alloc_zero(ctx, type, num) sss_sifp_alloc_zero(ctx, sizeof(type), num)

#define _free(ctx, var) \
    do { \
        ctx->free_fn((var), ctx->alloc_pvt); \
        (var) = NULL; \
    } while (0)

struct sss_sifp_ctx {
    DBusConnection *conn;
    sss_sifp_alloc_func *alloc_fn;
    sss_sifp_free_func *free_fn;
    void *alloc_pvt;

    DBusError *io_error;
};

enum sss_sifp_attr_type {
    SSS_SIFP_ATTR_TYPE_BOOL,
    SSS_SIFP_ATTR_TYPE_INT16,
    SSS_SIFP_ATTR_TYPE_UINT16,
    SSS_SIFP_ATTR_TYPE_INT32,
    SSS_SIFP_ATTR_TYPE_UINT32,
    SSS_SIFP_ATTR_TYPE_INT64,
    SSS_SIFP_ATTR_TYPE_UINT64,
    SSS_SIFP_ATTR_TYPE_STRING,
    SSS_SIFP_ATTR_TYPE_STRING_DICT
};

/**
 * D-Bus object attribute
 */
struct sss_sifp_attr {
    char *name;
    enum sss_sifp_attr_type type;
    unsigned int num_values;
    union {
        bool *boolean;
        int16_t *int16;
        uint16_t *uint16;
        int32_t *int32;
        uint32_t *uint32;
        int64_t *int64;
        uint64_t *uint64;
        char **str;
        hash_table_t *str_dict;
    } data;
};

void
sss_sifp_set_io_error(sss_sifp_ctx *ctx,
                      DBusError *error);

char *
sss_sifp_strdup(sss_sifp_ctx *ctx,
                const char *str);

char *
sss_sifp_strcat(sss_sifp_ctx *ctx,
                const char *str1,
                const char *str2);

sss_sifp_error
sss_sifp_parse_attr(sss_sifp_ctx *ctx,
                    const char *name,
                    DBusMessage *msg,
                    sss_sifp_attr ***_attrs);

sss_sifp_error
sss_sifp_parse_attr_list(sss_sifp_ctx *ctx,
                         DBusMessage *msg,
                         sss_sifp_attr ***_attrs);

sss_sifp_error
sss_sifp_parse_object_path(sss_sifp_ctx *ctx,
                           DBusMessage *msg,
                           char **_object_path);

sss_sifp_error
sss_sifp_parse_object_path_list(sss_sifp_ctx *ctx,
                                DBusMessage *msg,
                                char ***_object_paths);

#endif /* SSS_SIFP_PRIVATE_H_ */
