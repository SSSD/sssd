/*
 * System Security Services Daemon. NSS client interface
 *
 * Copyright (C) Simo Sorce 2011
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* NSS interfaces to mmap cache */

#ifndef _NSS_MC_H_
#define _NSS_MC_H_

#include <stdint.h>
#include <stdbool.h>
#include <pwd.h>
#include <grp.h>
#include "util/mmap_cache.h"

#ifndef HAVE_ERRNO_T
#define HAVE_ERRNO_T
typedef int errno_t;
#endif

/* common stuff */
struct sss_cli_mc_ctx {
    bool initialized;
    int fd;

    uint32_t seed;          /* seed from the tables header */

    void *mmap_base;        /* base address of mmap */
    size_t mmap_size;       /* total size of mmap */

    uint8_t *data_table;    /* data table address (in mmap) */
    uint32_t dt_size;       /* size of data table */

    uint32_t *hash_table;   /* hash table address (in mmap) */
    uint32_t ht_size;       /* size of hash table */
};

errno_t sss_nss_mc_get_ctx(const char *name, struct sss_cli_mc_ctx *ctx);
errno_t sss_nss_check_header(struct sss_cli_mc_ctx *ctx);
uint32_t sss_nss_mc_hash(struct sss_cli_mc_ctx *ctx,
                         const char *key, size_t len);
errno_t sss_nss_mc_get_record(struct sss_cli_mc_ctx *ctx,
                              uint32_t slot, struct sss_mc_rec **_rec);
errno_t sss_nss_str_ptr_from_buffer(char **str, void **cookie,
                                    char *buf, size_t len);

/* passwd db */
errno_t sss_nss_mc_getpwnam(const char *name, size_t name_len,
                            struct passwd *result,
                            char *buffer, size_t buflen);
errno_t sss_nss_mc_getpwuid(uid_t uid,
                            struct passwd *result,
                            char *buffer, size_t buflen);

/* group db */
errno_t sss_nss_mc_getgrnam(const char *name, size_t name_len,
                            struct group *result,
                            char *buffer, size_t buflen);
errno_t sss_nss_mc_getgrgid(gid_t gid,
                            struct group *result,
                            char *buffer, size_t buflen);

#endif /* _NSS_MC_H_ */
