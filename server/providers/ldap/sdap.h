/*
    SSSD

    LDAP Helper routines

    Copyright (C) Simo Sorce <ssorce@redhat.com>

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

#include "confdb/confdb.h"
#include "db/sysdb.h"
#include <ldap.h>

struct sdap_msg {
    struct sdap_msg *next;
    LDAPMessage *msg;
};

struct sdap_op;

typedef void (sdap_op_callback_t)(struct sdap_op *op,
                                  struct sdap_msg *, int, void *);

struct sdap_handle;

struct sdap_op {
    struct sdap_op *prev, *next;
    struct sdap_handle *sh;

    int msgid;
    bool done;

    sdap_op_callback_t *callback;
    void *data;

    struct tevent_context *ev;
    struct sdap_msg *list;
    struct sdap_msg *last;
};

struct sdap_handle {
    LDAP *ldap;
    bool connected;

    struct tevent_fd *fde;

    struct sdap_op *ops;
};

enum sdap_result {
    SDAP_SUCCESS,
    SDAP_NOT_FOUND,
    SDAP_UNAVAIL,
    SDAP_RETRY,
    SDAP_ERROR,
    SDAP_AUTH_SUCCESS,
    SDAP_AUTH_FAILED
};

#define SDAP_URI 0
#define SDAP_DEFAULT_BIND_DN 1
#define SDAP_DEFAULT_AUTHTOK_TYPE 2
#define SDAP_DEFAULT_AUTHTOK 3
#define SDAP_NETWROK_TIMEOUT 4
#define SDAP_OPT_TIMEOUT 5
#define SDAP_TLS_REQCERT 6
#define SDAP_USER_SEARCH_BASE 7
#define SDAP_USER_SEARCH_SCOPE 8
#define SDAP_USER_SEARCH_FILTER 9
#define SDAP_GROUP_SEARCH_BASE 10
#define SDAP_GROUP_SEARCH_SCOPE 11
#define SDAP_GROUP_SEARCH_FILTER 12
#define SDAP_SCHEMA 13
#define SDAP_OFFLINE_TIMEOUT 14
#define SDAP_FORCE_UPPER_CASE_REALM 15
#define SDAP_ENUM_REFRESH_TIMEOUT 16

#define SDAP_OPTS_BASIC 17 /* opts counter */

/* the objectclass must be the first attribute.
 * Functions depend on this */
#define SDAP_OC_USER 0
#define SDAP_AT_USER_NAME 1
#define SDAP_AT_USER_PWD 2
#define SDAP_AT_USER_UID 3
#define SDAP_AT_USER_GID 4
#define SDAP_AT_USER_GECOS 5
#define SDAP_AT_USER_HOME 6
#define SDAP_AT_USER_SHELL 7
#define SDAP_AT_USER_UUID 8
#define SDAP_AT_USER_PRINC 9
#define SDAP_AT_USER_FULLNAME 10
#define SDAP_AT_USER_MEMBEROF 11
#define SDAP_AT_USER_MODSTAMP 12

#define SDAP_OPTS_USER 13 /* attrs counter */

/* the objectclass must be the first attribute.
 * Functions depend on this */
#define SDAP_OC_GROUP 0
#define SDAP_AT_GROUP_NAME 1
#define SDAP_AT_GROUP_PWD 2
#define SDAP_AT_GROUP_GID 3
#define SDAP_AT_GROUP_MEMBER 4
#define SDAP_AT_GROUP_UUID 5
#define SDAP_AT_GROUP_MODSTAMP 6

#define SDAP_OPTS_GROUP 7 /* attrs counter */

struct sdap_gen_opts {
    const char *opt_name;
    const char *def_value;
    char *value;
};

struct sdap_id_map {
    const char *opt_name;
    const char *def_name;
    const char *sys_name;
    char *name;
};

struct sdap_options {
    struct sdap_gen_opts *basic;
    struct sdap_id_map *user_map;
    struct sdap_id_map *group_map;

    /* transformed for easier consumption */
    uint32_t default_authtok_size;
    char *default_authtok; /* todo: turn into uint8_t */
    int network_timeout;
    int opt_timeout;
    int offline_timeout;
    int enum_refresh_timeout;
    bool force_upper_case_realm;

    /* supported schema types */
    enum schema_type {
        SDAP_SCHEMA_RFC2307 = 1,    /* memberUid = uid */
        SDAP_SCHEMA_RFC2307BIS = 2, /* member = dn */
        SDAP_SCHEMA_IPA_V1 = 3      /* member/memberof with unrolling */
    } schema_type;
};

int sdap_get_options(TALLOC_CTX *memctx,
                     struct confdb_ctx *cdb,
                     const char *conf_path,
                     struct sdap_options **_opts);

int sdap_parse_user(TALLOC_CTX *memctx, struct sdap_options *opts,
                    struct sdap_handle *sh, struct sdap_msg *sm,
                    struct sysdb_attrs **_attrs, char **_dn);

int sdap_parse_group(TALLOC_CTX *memctx, struct sdap_options *opts,
                     struct sdap_handle *sh, struct sdap_msg *sm,
                     struct sysdb_attrs **_attrs, char **_dn);

int sdap_get_msg_dn(TALLOC_CTX *memctx, struct sdap_handle *sh,
                    struct sdap_msg *sm, char **_dn);
