/*
    SSSD

    Kerberos Backend, private header file

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#ifndef __KRB5_AUTH_H__
#define __KRB5_AUTH_H__

#define MAX_CHILD_MSG_SIZE 255
#define CCACHE_ENV_NAME "KRB5CCNAME"

typedef enum { INIT_PW, INIT_KT, RENEW, VALIDATE } action_type;

struct krb5_ctx {
    /* opts taken from kinit */
    /* in seconds */
    krb5_deltat starttime;
    krb5_deltat lifetime;
    krb5_deltat rlife;

    int forwardable;
    int proxiable;
    int addresses;

    int not_forwardable;
    int not_proxiable;
    int no_addresses;

    int verbose;

    char* principal_name;
    char* service_name;
    char* keytab_name;
    char* k5_cache_name;
    char* k4_cache_name;

    action_type action;

    int num_pa_opts;
    krb5_gic_opt_pa_data *pa_opts;

    char *kdcip;
    char *realm;
};

struct krb5_req {
    krb5_context ctx;
    krb5_ccache cc;
    krb5_principal princ;
    char* name;
    krb5_creds *creds;
    krb5_get_init_creds_opt *options;
    pid_t child_pid;
    int fd;

    struct be_req *req;
    struct pam_data *pd;
    struct krb5_ctx *krb5_ctx;
};

static krb5_context krb5_error_ctx;
static const char *__krb5_error_msg;
#define KRB5_DEBUG(level, krb5_error) do { \
    __krb5_error_msg = krb5_get_error_message(krb5_error_ctx, krb5_error); \
    DEBUG(level, ("%d: [%d][%s]\n", __LINE__, krb5_error, __krb5_error_msg)); \
    krb5_free_error_message(krb5_error_ctx, __krb5_error_msg); \
} while(0);

void tgt_req_child(int fd, struct krb5_req *kr);

#endif /* __KRB5_AUTH_H__ */
