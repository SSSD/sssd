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

#include <popt.h>

#include "util/util.h"

#define SSSD_PIDFILE ""PID_PATH"/sssd.pid"
#define MAX_PID_LENGTH 10

#define BAD_POPT_PARAMS(pc, msg, val, label) do { \
        usage(pc, msg);                           \
        val = EXIT_FAILURE;                       \
        goto label;                               \
} while(0)

#define CHECK_ROOT(val, prg_name) do { \
    val = getuid(); \
    if (val != 0) { \
        DEBUG(1, ("Running under %d, must be root\n", val)); \
        ERROR("%1$s must be run as root\n", prg_name); \
        val = EXIT_FAILURE; \
        goto fini; \
    } \
} while(0)

struct tools_ctx {
    struct confdb_ctx *confdb;
    struct sysdb_ctx *sysdb;

    struct sss_names_ctx *snctx;
    struct sss_domain_info *local;

    struct ops_ctx *octx;

    bool transaction_done;
    int error;
};

int init_sss_tools(struct tools_ctx **_tctx);

void usage(poptContext pc, const char *error);

int set_locale(void);


int parse_name_domain(struct tools_ctx *tctx,
                      const char *fullname);

int id_in_range(uint32_t id,
                struct sss_domain_info *dom);

int parse_groups(TALLOC_CTX *mem_ctx,
                 const char *optstr,
                 char ***_out);

int parse_group_name_domain(struct tools_ctx *tctx,
                            char **groups);

int check_group_names(struct tools_ctx *tctx,
                      char **grouplist,
                      char **badgroup);

int create_homedir(const char *skeldir,
                   const char *homedir,
                   uid_t uid,
                   gid_t gid,
                   mode_t default_umask);

int create_mail_spool(TALLOC_CTX *mem_ctx,
                      const char *username,
                      const char *maildir,
                      uid_t uid, gid_t gid);

int remove_homedir(TALLOC_CTX *mem_ctx,
                   const char *homedir,
                   const char *maildir,
                   const char *username,
                   uid_t uid, bool force);

int run_userdel_cmd(struct tools_ctx *tctx);

errno_t signal_sssd(int signum);

/* tools_mc_util.c */
errno_t sss_memcache_invalidate(const char *mc_filename);

errno_t sss_memcache_clear_all(void);

errno_t sss_mc_refresh_user(const char *username);
errno_t sss_mc_refresh_group(const char *groupname);
errno_t sss_mc_refresh_grouplist(struct tools_ctx *tctx,
                                 char **groupnames);

/* from files.c */
int remove_tree(const char *root);

int copy_tree(const char *src_root, const char *dst_root,
              mode_t mode_root, uid_t uid, gid_t gid);

/* from nscd.c */
enum nscd_db {
    NSCD_DB_PASSWD,
    NSCD_DB_GROUP
};

int flush_nscd_cache(enum nscd_db flush_db);

/* from selinux.c */
int selinux_file_context(const char *dst_name);
int reset_selinux_file_context(void);
int set_seuser(const char *login_name, const char *seuser_name);
int del_seuser(const char *login_name);

#endif  /* __TOOLS_UTIL_H__ */
