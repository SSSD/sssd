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

#include "config.h"

#include <stdbool.h>

#ifdef HAVE_KRB5_KRB5_H
#include <krb5/krb5.h>
#else
#include <krb5.h>
#endif

#define MAX_CHILD_MSG_SIZE 255
#define CCACHE_ENV_NAME "KRB5CCNAME"

#define SSSD_KRB5_CHANGEPW_PRINCIPLE "SSSD_KRB5_CHANGEPW_PRINCIPLE"
#define SSSD_KRB5_KDC "SSSD_KRB5_KDC"
#define SSSD_KRB5_REALM "SSSD_KRB5_REALM"


typedef enum { INIT_PW, INIT_KT, RENEW, VALIDATE } action_type;

struct krb5child_req {
    pid_t child_pid;
    int read_from_child_fd;
    int write_to_child_fd;

    struct be_req *req;
    struct pam_data *pd;
    struct krb5_ctx *krb5_ctx;

    struct tevent_timer *timeout_handler;

    char *ccname;
    const char *homedir;
};

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

    char *kdcip;
    char *realm;
    char *changepw_principle;
    char *ccache_dir;
    char *ccname_template;
    int auth_timeout;
    int child_debug_fd;
};

#endif /* __KRB5_AUTH_H__ */
