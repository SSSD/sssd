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
    SDAP_AUTH_FAILED,
    SDAP_AUTH_PW_EXPIRED
};

enum sdap_basic_opt {
    SDAP_URI = 0,
    SDAP_DEFAULT_BIND_DN,
    SDAP_DEFAULT_AUTHTOK_TYPE,
    SDAP_DEFAULT_AUTHTOK,
    SDAP_SEARCH_TIMEOUT,
    SDAP_NETWORK_TIMEOUT,
    SDAP_OPT_TIMEOUT,
    SDAP_TLS_REQCERT,
    SDAP_USER_SEARCH_BASE,
    SDAP_USER_SEARCH_SCOPE,
    SDAP_USER_SEARCH_FILTER,
    SDAP_GROUP_SEARCH_BASE,
    SDAP_GROUP_SEARCH_SCOPE,
    SDAP_GROUP_SEARCH_FILTER,
    SDAP_SCHEMA,
    SDAP_OFFLINE_TIMEOUT,
    SDAP_FORCE_UPPER_CASE_REALM,
    SDAP_ENUM_REFRESH_TIMEOUT,
    SDAP_STALE_TIME,
    SDAP_TLS_CACERT,
    SDAP_TLS_CACERTDIR,
    SDAP_ID_TLS,
    SDAP_SASL_MECH,
    SDAP_SASL_AUTHID,
    SDAP_KRB5_KEYTAB,
    SDAP_KRB5_KINIT,
    SDAP_KRB5_REALM,

    SDAP_OPTS_BASIC /* opts counter */
};

/* the objectclass must be the first attribute.
 * Functions depend on this */
enum sdap_user_opt {
    SDAP_OC_USER = 0,
    SDAP_AT_USER_NAME,
    SDAP_AT_USER_PWD,
    SDAP_AT_USER_UID,
    SDAP_AT_USER_GID,
    SDAP_AT_USER_GECOS,
    SDAP_AT_USER_HOME,
    SDAP_AT_USER_SHELL,
    SDAP_AT_USER_PRINC,
    SDAP_AT_USER_FULLNAME,
    SDAP_AT_USER_MEMBEROF,
    SDAP_AT_USER_UUID,
    SDAP_AT_USER_MODSTAMP,

    SDAP_OPTS_USER /* attrs counter */
};

/* the objectclass must be the first attribute.
 * Functions depend on this */
enum sdap_group_opt {
    SDAP_OC_GROUP = 0,
    SDAP_AT_GROUP_NAME,
    SDAP_AT_GROUP_PWD,
    SDAP_AT_GROUP_GID,
    SDAP_AT_GROUP_MEMBER,
    SDAP_AT_GROUP_UUID,
    SDAP_AT_GROUP_MODSTAMP,

    SDAP_OPTS_GROUP /* attrs counter */
};

enum sdap_type {
    SDAP_STRING,
    SDAP_BLOB,
    SDAP_NUMBER,
    SDAP_BOOL
};

struct sdap_blob {
    uint8_t *data;
    size_t length;
};

union sdap_value {
    const char *cstring;
    char *string;
    struct sdap_blob blob;
    int number;
    bool boolean;
};

struct sdap_gen_opts {
    const char *opt_name;
    enum sdap_type type;
    union sdap_value def_val;
    union sdap_value val;
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

    /* supported schema types */
    enum schema_type {
        SDAP_SCHEMA_RFC2307 = 1,    /* memberUid = uid */
        SDAP_SCHEMA_RFC2307BIS = 2, /* member = dn */
        SDAP_SCHEMA_IPA_V1 = 3      /* member/memberof with unrolling */
    } schema_type;

    struct ldb_dn *users_base;
    struct ldb_dn *groups_base;
};

int sdap_get_options(TALLOC_CTX *memctx,
                     struct confdb_ctx *cdb,
                     const char *conf_path,
                     struct sdap_options **_opts);

const char *_sdap_go_get_cstring(struct sdap_gen_opts *opts,
                                 int id, const char *location);
char *_sdap_go_get_string(struct sdap_gen_opts *opts,
                          int id, const char *location);
struct sdap_blob _sdap_go_get_blob(struct sdap_gen_opts *opts,
                                   int id, const char *location);
int _sdap_go_get_int(struct sdap_gen_opts *opts,
                     int id, const char *location);
bool _sdap_go_get_bool(struct sdap_gen_opts *opts,
                       int id, const char *location);
#define sdap_go_get_cstring(o, i) _sdap_go_get_cstring(o, i, __FUNCTION__)
#define sdap_go_get_string(o, i) _sdap_go_get_string(o, i, __FUNCTION__)
#define sdap_go_get_blob(o, i) _sdap_go_get_blob(o, i, __FUNCTION__)
#define sdap_go_get_int(o, i) _sdap_go_get_int(o, i, __FUNCTION__)
#define sdap_go_get_bool(o, i) _sdap_go_get_bool(o, i, __FUNCTION__)

int sdap_parse_user(TALLOC_CTX *memctx, struct sdap_options *opts,
                    struct sdap_handle *sh, struct sdap_msg *sm,
                    struct sysdb_attrs **_attrs, char **_dn);

int sdap_parse_group(TALLOC_CTX *memctx, struct sdap_options *opts,
                     struct sdap_handle *sh, struct sdap_msg *sm,
                     struct sysdb_attrs **_attrs, char **_dn);

int sdap_get_msg_dn(TALLOC_CTX *memctx, struct sdap_handle *sh,
                    struct sdap_msg *sm, char **_dn);

errno_t setup_tls_config(struct sdap_gen_opts *basic_opts);
