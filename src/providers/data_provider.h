/*
   SSSD

   Data Provider, private header file

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

#ifndef __DATA_PROVIDER_H__
#define __DATA_PROVIDER_H__

#include "config.h"

#include <stdint.h>
#include <sys/un.h>
#include <errno.h>
#include <stdbool.h>
#ifdef USE_KEYRING
#include <sys/types.h>
#include <keyutils.h>
#endif
#include <talloc.h>
#include <tevent.h>
#include <ldb.h>
#include <dbus/dbus.h>

#include "util/util.h"
#include "confdb/confdb.h"
#include "sss_client/sss_cli.h"
#include "util/authtok.h"
#include "util/sss_pam_data.h"
#include "providers/data_provider_req.h"

#define DATA_PROVIDER_VERSION 0x0001

/**
 * @defgroup pamHandler PAM DBUS request
 * @ingroup sss_pam
 *
 * The PAM responder send all the data it has received from the PAM client to
 * the authentication backend with a DBUS message.
 *
 * As a response it expects a PAM return value (see pam(3) for details).
 * The backend may send any number of additional messages (see ...) which are
 * forwarded by the PAM responder to the PAM client.
 * @{
 */

/** Then pamHandler Request
 *
 * The following two functions can help you to pack and unpack the DBUS
 * message for a PAM request. If it is necessary to create the DBUS message by
 * hand it must have the following elements:
 *
 * @param DBUS_TYPE_INT32 PAM Command, see #sss_cli_command for allowed values
 * @param DBUS_TYPE_STRING User name, this value is send by the PAM client and
 * contains the value of the PAM item PAM_USER
 * @param DBUS_TYPE_STRING Service name, this value is send by the PAM client
 * and contains the value of the PAM item PAM_SERVICE
 * @param DBUS_TYPE_STRING TTY name this value is send by the PAM client and
 * contains the value of the PAM item PAM_TTY
 * @param DBUS_TYPE_STRING Remote user, this value is send by the PAM client
 * and contains the value of the PAM item PAM_RUSER
 * @param DBUS_TYPE_STRING Remote host, this value is send by the PAM client
 * and contains the value of the PAM item PAM_RHOST
 * @param DBUS_TYPE_UINT32 Type of the authentication token, see #sss_authtok_type
 * for allowed values
 * @param DBUS_TYPE_ARRAY__(BYTE) Authentication token, DBUS array which
 * contains the authentication token, it is not required that passwords have a
 * trailing \\0, this value is send by the PAM client and contains the value of
 * the PAM item PAM_AUTHTOK or PAM_OLDAUTHTOK if the PAM command is
 * #SSS_PAM_CHAUTHTOK or #SSS_PAM_CHAUTHTOK_PRELIM
 * @param DBUS_TYPE_UINT32 Type of the new authentication token, see
 * #sss_authtok_type for allowed values
 * @param DBUS_TYPE_ARRAY__(BYTE) New authentication token, DBUS array which
 * contains the new authentication token for a password change, it is not
 * required that passwords have a trailing \\0, this value is send by the PAM
 * client and contains the value of the PAM item PAM_AUTHTOK if the PAM
 * command is #SSS_PAM_CHAUTHTOK or #SSS_PAM_CHAUTHTOK_PRELIM
 * @param DBUS_TYPE_INT32 Privileged flag is set to a non-zero value if the
 * PAM client connected to the PAM responder via the privileged pipe, i.e. if
 * the PAM client is running with root privileges
 * @param DBUS_TYPE_UINT32
 *
 * @retval DBUS_TYPE_UINT32 PAM return value, PAM_AUTHINFO_UNAVAIL is used to
 * indicate that the provider is offline and that the PAM responder should try
 * a cached authentication, for all other return value see the man pages for
 * the corresponding PAM service functions
 * @retval DBUS_TYPE_ARRAY__(STRUCT) Zero or more additional getAccountInfo
 * messages, here the DBUS_TYPE_STRUCT is build of a DBUS_TYPE_UINT32 holding
 * an identifier (see #response_type) and DBUS_TYPE_G_BYTE_ARRAY with the data
 * of the message.
 */


/**
 * @}
 */ /* end of group pamHandler */

#define DP_ERR_DECIDE -1
#define DP_ERR_OK 0
#define DP_ERR_OFFLINE 1
#define DP_ERR_TIMEOUT 2
#define DP_ERR_FATAL 3

#define BE_FILTER_NAME 1
#define BE_FILTER_IDNUM 2
#define BE_FILTER_ENUM 3
#define BE_FILTER_SECID 4
#define BE_FILTER_UUID 5
#define BE_FILTER_CERT 6
#define BE_FILTER_WILDCARD 7
#define BE_FILTER_ADDR 8

#define DP_SEC_ID "secid"
#define DP_CERT "cert"
/* sizeof() counts the trailing \0 so we must subtract 1 for the string
 * length */
#define DP_SEC_ID_LEN (sizeof(DP_SEC_ID) - 1)
#define DP_CERT_LEN (sizeof(DP_CERT) - 1)

#define DP_WILDCARD "wildcard"
#define DP_WILDCARD_LEN (sizeof(DP_WILDCARD) - 1)

#define EXTRA_NAME_IS_UPN "U"
#define EXTRA_INPUT_MAYBE_WITH_VIEW "V"

/* from dp_auth_util.c */
#define SSS_SERVER_INFO 0x80000000

#define SSS_KRB5_INFO 0x40000000
#define SSS_LDAP_INFO 0x20000000
#define SSS_PROXY_INFO 0x10000000

#define SSS_KRB5_INFO_TGT_LIFETIME (SSS_SERVER_INFO|SSS_KRB5_INFO|0x01)
#define SSS_KRB5_INFO_UPN (SSS_SERVER_INFO|SSS_KRB5_INFO|0x02)

bool dp_pack_pam_request(DBusMessage *msg, struct pam_data *pd);
bool dp_unpack_pam_request(DBusMessage *msg, TALLOC_CTX *mem_ctx,
                           struct pam_data **new_pd, DBusError *dbus_error);

bool dp_pack_pam_response(DBusMessage *msg, struct pam_data *pd);
bool dp_unpack_pam_response(DBusMessage *msg, struct pam_data *pd,
                            DBusError *dbus_error);

void dp_id_callback(DBusPendingCall *pending, void *ptr);

#ifdef BUILD_FILES_PROVIDER
/* Reserved filter name for request which waits until the files provider finishes mirroring
 * the file content
 */
#define DP_REQ_OPT_FILES_INITGR     "files_initgr_request"
#endif

/* Helpers */

#define NULL_STRING { .string = NULL }
#define NULL_BLOB { .blob = { NULL, 0 } }
#define NULL_NUMBER { .number = 0 }
#define BOOL_FALSE { .boolean = false }
#define BOOL_TRUE { .boolean = true }

enum dp_opt_type {
    DP_OPT_STRING,
    DP_OPT_BLOB,
    DP_OPT_NUMBER,
    DP_OPT_BOOL
};

struct dp_opt_blob {
    uint8_t *data;
    size_t length;
};

union dp_opt_value {
    const char *cstring;
    char *string;
    struct dp_opt_blob blob;
    int number;
    bool boolean;
};

struct dp_option {
    const char *opt_name;
    enum dp_opt_type type;
    union dp_opt_value def_val;
    union dp_opt_value val;
};

#define DP_OPTION_TERMINATOR { NULL, 0, NULL_STRING, NULL_STRING }

void dp_option_inherit_match(char **inherit_opt_list,
                             int option,
                             struct dp_option *parent_opts,
                             struct dp_option *subdom_opts);

void dp_option_inherit(int option,
                       struct dp_option *parent_opts,
                       struct dp_option *subdom_opts);

int dp_get_options(TALLOC_CTX *memctx,
                   struct confdb_ctx *cdb,
                   const char *conf_path,
                   struct dp_option *def_opts,
                   int num_opts,
                   struct dp_option **_opts);

int dp_copy_options(TALLOC_CTX *memctx,
                    struct dp_option *src_opts,
                    int num_opts,
                    struct dp_option **_opts);

int dp_copy_defaults(TALLOC_CTX *memctx,
                     struct dp_option *src_opts,
                     int num_opts,
                     struct dp_option **_opts);

const char *_dp_opt_get_cstring(struct dp_option *opts,
                                    int id, const char *location);
char *_dp_opt_get_string(struct dp_option *opts,
                                    int id, const char *location);
struct dp_opt_blob _dp_opt_get_blob(struct dp_option *opts,
                                    int id, const char *location);
int _dp_opt_get_int(struct dp_option *opts,
                                    int id, const char *location);
bool _dp_opt_get_bool(struct dp_option *opts,
                                    int id, const char *location);
#define dp_opt_get_cstring(o, i) _dp_opt_get_cstring(o, i, __FUNCTION__)
#define dp_opt_get_string(o, i) _dp_opt_get_string(o, i, __FUNCTION__)
#define dp_opt_get_blob(o, i) _dp_opt_get_blob(o, i, __FUNCTION__)
#define dp_opt_get_int(o, i) _dp_opt_get_int(o, i, __FUNCTION__)
#define dp_opt_get_bool(o, i) _dp_opt_get_bool(o, i, __FUNCTION__)

int _dp_opt_set_string(struct dp_option *opts, int id,
                       const char *s, const char *location);
int _dp_opt_set_blob(struct dp_option *opts, int id,
                     struct dp_opt_blob b, const char *location);
int _dp_opt_set_int(struct dp_option *opts, int id,
                    int i, const char *location);
int _dp_opt_set_bool(struct dp_option *opts, int id,
                     bool b, const char *location);
#define dp_opt_set_string(o, i, v) _dp_opt_set_string(o, i, v, __FUNCTION__)
#define dp_opt_set_blob(o, i, v) _dp_opt_set_blob(o, i, v, __FUNCTION__)
#define dp_opt_set_int(o, i, v) _dp_opt_set_int(o, i, v, __FUNCTION__)
#define dp_opt_set_bool(o, i, v) _dp_opt_set_bool(o, i, v, __FUNCTION__)

/* Generic Data Provider options */

/* Resolver DP options */
enum dp_res_opts {
    DP_RES_OPT_FAMILY_ORDER,
    DP_RES_OPT_RESOLVER_TIMEOUT,
    DP_RES_OPT_RESOLVER_OP_TIMEOUT,
    DP_RES_OPT_RESOLVER_SERVER_TIMEOUT,
    DP_RES_OPT_RESOLVER_USE_SEARCH_LIST,
    DP_RES_OPT_DNS_DOMAIN,

    DP_RES_OPTS /* attrs counter */
};

#endif /* __DATA_PROVIDER_ */
