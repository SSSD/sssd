/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2009 Red Hat

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


#ifndef __TOOLS_UTIL_H__
#define __TOOLS_UTIL_H__

#include "util/sssd-i18n.h"

#define CHECK_ROOT(val, prg_name) do { \
    val = getuid(); \
    if (val != 0) { \
        DEBUG(1, ("Running under %d, must be root\n", val)); \
        ERROR("%s must be run as root\n", prg_name); \
        val = EXIT_FAILURE; \
        goto fini; \
    } \
} while(0)

struct tools_ctx {
    struct tevent_context *ev;
    struct confdb_ctx *confdb;
    struct sysdb_ctx *sysdb;
    struct sss_names_ctx *snctx;

    struct sss_domain_info *domains;
};

struct ops_ctx {
    struct tools_ctx *ctx;
    struct sss_domain_info *domain;

    char *name;
    uid_t uid;
    gid_t gid;
    char *gecos;
    char *home;
    char *shell;
    struct sysdb_attrs *attrs;

    char **addgroups;
    char **rmgroups;
    char **groups;
    int cur;

    struct sysdb_handle *handle;
    int error;
    bool done;
};

int init_sss_tools(struct ops_ctx **_octx);

void usage(poptContext pc, const char *error);

int set_locale(void);

int get_domain(struct ops_ctx *octx,
               const char *fullname);

int id_in_range(uint32_t id,
                struct sss_domain_info *dom);

int parse_groups(TALLOC_CTX *mem_ctx,
                 const char *optstr,
                 char ***_out);

#endif  /* __TOOLS_UTIL_H__ */
