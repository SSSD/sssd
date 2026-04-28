/*
    SSSD

    Himmelblau Provider - Common definitions

    Authors:
        David Mulder <dmulder@suse.com>

    Copyright (C) 2026 SUSE

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

#ifndef _HIMMELBLAU_COMMON_H_
#define _HIMMELBLAU_COMMON_H_

#include "providers/data_provider/dp.h"
#include "providers/backend.h"

/* libhimmelblau C API */
#include <himmelblau.h>

/* ID mapping library */
#include "lib/idmap/sss_idmap.h"

/* Sysdb attributes for device enrollment (custom object) */
#define SYSDB_HIMMELBLAU_DEVICE_ID "himmelblauDeviceId"
#define SYSDB_HIMMELBLAU_AUTH_VALUE "himmelblauAuthValue"
#define SYSDB_HIMMELBLAU_TRANSPORT_KEY "himmelblauTransportKey"
#define SYSDB_HIMMELBLAU_CERT_KEY "himmelblauCertKey"
#define SYSDB_HIMMELBLAU_ENROLLED_AT "himmelblauEnrolledAt"

/* Per-user token uses predefined SYSDB_REFRESH_TOKEN from sysdb.h */
#define SYSDB_HIMMELBLAU_TOKEN_EXPIRE "himmelblauTokenExpire"

/* Custom object names */
#define HIMMELBLAU_DEVICE_SUBDIR "himmelblau"
#define HIMMELBLAU_DEVICE_OBJ "device"

/* Context structures */
struct himmelblau_init_ctx {
    struct be_ctx *be_ctx;
    struct dp_option *opts;

    char *domain;

    /* Shared broker instance for auth and id operations */
    BrokerClientApplication *broker;
    bool broker_initialized;

    /* Shared TPM and machine key for device enrollment */
    BoxedDynTpm *tpm;
    bool tpm_initialized;
    char *auth_value;
    LoadableMachineKey *loadable_machine_key;
    MachineKey *machine_key;
    bool machine_key_initialized;

    /* Device enrollment keys (persisted after enrollment) */
    LoadableMsOapxbcRsaKey *transport_key_obj;
    LoadableMsDeviceEnrolmentKey *cert_key_obj;
    bool enrollment_keys_loaded;

    struct himmelblau_auth_ctx *auth_ctx;
    struct himmelblau_id_ctx *id_ctx;
};

struct himmelblau_auth_ctx {
    struct be_ctx *be_ctx;
    struct himmelblau_init_ctx *init_ctx;

    char *domain;
};

struct himmelblau_id_ctx {
    struct be_ctx *be_ctx;
    struct himmelblau_init_ctx *init_ctx;

    char *domain;

    /* ID mapping context */
    struct sss_idmap_ctx *idmap_ctx;
};

/* Auth handler (himmelblau_auth.c) */
struct tevent_req *
himmelblau_pam_handler_send(TALLOC_CTX *mem_ctx,
                           struct himmelblau_auth_ctx *auth_ctx,
                           struct pam_data *pd,
                           struct dp_req_params *params);

errno_t
himmelblau_pam_handler_recv(TALLOC_CTX *mem_ctx,
                           struct tevent_req *req,
                           struct pam_data **_data);

/* ID handler (himmelblau_id.c) */
struct tevent_req *
himmelblau_account_info_handler_send(TALLOC_CTX *mem_ctx,
                                    struct himmelblau_id_ctx *id_ctx,
                                    struct dp_id_data *data,
                                    struct dp_req_params *params);

errno_t
himmelblau_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                    struct tevent_req *req,
                                    struct dp_reply_std *data);

/* Device enrollment (domain-wide) - sysdb storage */
errno_t
himmelblau_sysdb_save_device_enrollment(
    struct sss_domain_info *domain,
    const char *device_id,
    const char *auth_value,
    LoadableMsOapxbcRsaKey *transport_key,
    LoadableMsDeviceEnrolmentKey *cert_key);

errno_t
himmelblau_sysdb_load_device_enrollment(
    TALLOC_CTX *mem_ctx,
    struct sss_domain_info *domain,
    char **_device_id,
    char **_auth_value,
    LoadableMsOapxbcRsaKey **_transport_key,
    LoadableMsDeviceEnrolmentKey **_cert_key);

errno_t
himmelblau_sysdb_check_device_enrolled(
    struct sss_domain_info *domain,
    bool *_enrolled);

errno_t
himmelblau_sysdb_delete_device_enrollment(
    struct sss_domain_info *domain);

/* Per-user refresh tokens - sysdb storage */
errno_t
himmelblau_sysdb_save_refresh_token(
    struct sss_domain_info *domain,
    const char *username,
    const char *refresh_token);

errno_t
himmelblau_sysdb_load_refresh_token(
    TALLOC_CTX *mem_ctx,
    struct sss_domain_info *domain,
    const char *username,
    char **_refresh_token);

errno_t
himmelblau_sysdb_delete_refresh_token(
    struct sss_domain_info *domain,
    const char *username);

/* Error mapping (himmelblau_util.c) */
int
himmelblau_error_to_pam_status(errno_t himmelblau_error,
                               MSAL_ERROR *error_obj);

const char *
himmelblau_pam_status_to_string(int pam_status);

/* Device enrollment (himmelblau_auth.c) */
struct tevent_req *
himmelblau_enroll_device_send(TALLOC_CTX *mem_ctx,
                              struct tevent_context *ev,
                              struct himmelblau_init_ctx *init_ctx,
                              const char *refresh_token);

errno_t
himmelblau_enroll_device_recv(struct tevent_req *req,
                              TALLOC_CTX *mem_ctx,
                              char **_device_id);

/* MFA authentication (himmelblau_auth.c) */
struct tevent_req *
himmelblau_authenticate_user_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct himmelblau_init_ctx *init_ctx,
                                  struct pam_data *pd,
                                  const char *username,
                                  const char *password);

errno_t
himmelblau_authenticate_user_recv(struct tevent_req *req,
                                 TALLOC_CTX *mem_ctx,
                                 UserToken **_token);

/* User lookup (himmelblau_id.c) */
struct tevent_req *
himmelblau_get_user_by_name_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct himmelblau_id_ctx *id_ctx,
                                  const char *username);

errno_t
himmelblau_get_user_by_name_recv(struct tevent_req *req,
                                 bool *_user_exists);

#endif /* _HIMMELBLAU_COMMON_H_ */
