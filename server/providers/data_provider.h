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

#include <stdint.h>
#include <sys/un.h>
#include <errno.h>
#include <stdbool.h>
#include "talloc.h"
#include "tevent.h"
#include "ldb.h"
#include "util/util.h"
#include "confdb/confdb.h"
#include "dbus/dbus.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sbus_client.h"
#include "providers/dp_interfaces.h"
#include "../sss_client/sss_cli.h"

#define DATA_PROVIDER_VERSION 0x0001
#define DATA_PROVIDER_SERVICE_NAME "dp"
#define DATA_PROVIDER_PIPE "private/sbus-dp"

#define DATA_PROVIDER_DB_FILE "sssd.ldb"
#define DATA_PROVIDER_DB_CONF_SEC "config/services/nss"

#define MOD_OFFLINE 0x0000
#define MOD_ONLINE  0x0001

#define DP_CLI_INTERFACE "org.freedesktop.sssd.dataprovider"
#define DP_CLI_PATH "/org/freedesktop/sssd/dataprovider"

#define DP_CLI_BACKEND 0x0001
#define DP_CLI_FRONTEND 0x0002
#define DP_CLI_TYPE_MASK 0x0003

#define DP_CLI_PROVIDE_ACC_INFO (1<<8)
#define DP_CLI_PROVIDE_PAM (1<<9)
#define DP_CLI_PROVIDE_POLICY (1<<10)

#define DP_CLI_METHOD_ONLINE "getOnline"
#define DP_CLI_METHOD_GETACCTINFO "getAccountInfo"
#define DP_CLI_METHOD_PAMHANDLER "pamHandler"

#define DP_SRV_METHOD_REGISTER "RegisterService"
#define DP_SRV_METHOD_GETACCTINFO "getAccountInfo"
#define DP_SRV_METHOD_PAMHANDLER "pamHandler"

#define DP_ERR_OK 0
#define DP_ERR_OFFLINE 1
#define DP_ERR_TIMEOUT 2
#define DP_ERR_FATAL 3

#define BE_ATTR_CORE 1
#define BE_ATTR_MEM 2
#define BE_ATTR_ALL 3

#define BE_FILTER_NAME 1
#define BE_FILTER_IDNUM 2

#define BE_REQ_USER 1
#define BE_REQ_GROUP 2
#define BE_REQ_INITGROUPS 3

/* AUTH related common data and functions */

#define DEBUG_PAM_DATA(level, pd) do { \
    if (level <= debug_level) pam_print_data(level, pd); \
} while(0);


struct response_data {
    int32_t type;
    int32_t len;
    uint8_t *data;
    struct response_data *next;
};

struct pam_data {
    int cmd;
    uint32_t authtok_type;
    uint32_t authtok_size;
    uint32_t newauthtok_type;
    uint32_t newauthtok_size;
    char *domain;
    char *user;
    char *service;
    char *tty;
    char *ruser;
    char *rhost;
    uint8_t *authtok;
    uint8_t *newauthtok;

    int pam_status;
    int response_delay;
    struct response_data *resp_list;

    bool offline_auth;
    int priv;
    uid_t pw_uid;
    gid_t gr_gid;
};

/* from dp_auth_util.c */
void pam_print_data(int l, struct pam_data *pd);
int pam_add_response(struct pam_data *pd,
                     enum response_type type,
                     int len, const uint8_t *data);

bool dp_pack_pam_request(DBusMessage *msg, struct pam_data *pd);
bool dp_unpack_pam_request(DBusMessage *msg, struct pam_data *pd,
                           DBusError *dbus_error);

bool dp_pack_pam_response(DBusMessage *msg, struct pam_data *pd);
bool dp_unpack_pam_response(DBusMessage *msg, struct pam_data *pd,
                            DBusError *dbus_error);

int dp_common_send_id(struct sbus_connection *conn,
                      uint16_t cli_type, uint16_t version,
                      const char *name, const char *domain);

/* from dp_sbus.c */
int dp_get_sbus_address(TALLOC_CTX *mem_ctx, struct confdb_ctx *confdb,
                        char **address);


#endif /* __DATA_PROVIDER_ */
