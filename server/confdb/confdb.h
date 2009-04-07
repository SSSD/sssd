/*
   SSSD

   NSS Configuratoin DB

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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

#ifndef _CONF_DB_H
#define _CONF_DB_H

#include <stdbool.h>
#include "talloc.h"
#include "tevent.h"
#include "util/btreemap.h"

#define CONFDB_FILE "config.ldb"
#define SSSD_MIN_ID 1000

struct sss_domain_info {
    char *name;
    char *provider;
    int timeout;
    int enumerate;
    bool fqnames;
    bool legacy;
    bool mpg;
    uint32_t id_min;
    uint32_t id_max;

    struct sss_domain_info *next;
};

struct confdb_ctx;

int confdb_add_param(struct confdb_ctx *cdb,
                     bool replace,
                     const char *section,
                     const char *attribute,
                     const char **values);


int confdb_get_param(struct confdb_ctx *cdb,
                     TALLOC_CTX *mem_ctx,
                     const char *section,
                     const char *attribute,
                     char ***values);

int confdb_get_string(struct confdb_ctx *cdb, TALLOC_CTX *ctx,
                      const char *section, const char *attribute,
                      const char *defstr, char **result);

int confdb_get_int(struct confdb_ctx *cdb, TALLOC_CTX *ctx,
                   const char *section, const char *attribute,
                   int defval, int *result);

int confdb_get_bool(struct confdb_ctx *cdb, TALLOC_CTX *ctx,
                    const char *section, const char *attribute,
                    bool defval, bool *result);

int confdb_init(TALLOC_CTX *mem_ctx,
                struct tevent_context *ev,
                struct confdb_ctx **cdb_ctx,
                char *confdb_location);

int confdb_get_domains(struct confdb_ctx *cdb,
                       TALLOC_CTX *mem_ctx,
                       struct sss_domain_info **domains);

#endif
