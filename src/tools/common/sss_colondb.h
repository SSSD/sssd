/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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

#ifndef _SSS_COLONDB_H_
#define _SSS_COLONDB_H_

#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <talloc.h>

struct sss_colondb;

enum sss_colondb_mode {
    SSS_COLONDB_READ,
    SSS_COLONDB_WRITE
};

enum sss_colondb_type {
    SSS_COLONDB_UINT32,
    SSS_COLONDB_STRING,
    SSS_COLONDB_SENTINEL
};

union sss_colondb_write_data {
    uint32_t uint32;
    const char *str;
};

union sss_colondb_read_data {
    uint32_t *uint32;
    const char **str;
};

struct sss_colondb_write_field {
    enum sss_colondb_type type;
    union sss_colondb_write_data data;
};

struct sss_colondb_read_field {
    enum sss_colondb_type type;
    union sss_colondb_read_data data;
};

struct sss_colondb *sss_colondb_open(TALLOC_CTX *mem_ctx,
                                     enum sss_colondb_mode mode,
                                     const char *filename);

errno_t sss_colondb_readline(TALLOC_CTX *mem_ctx,
                             struct sss_colondb *db,
                             struct sss_colondb_read_field *table);

errno_t sss_colondb_writeline(struct sss_colondb *db,
                              struct sss_colondb_write_field *table);

#endif /* _SSS_COLONDB_H_ */
