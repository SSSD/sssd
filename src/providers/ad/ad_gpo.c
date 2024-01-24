/*
    SSSD

    Authors:
        Yassir Elley <yelley@redhat.com>

    Copyright (C) 2013 Red Hat

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

/*
 * This file implements the following pair of *public* functions (see header):
 *   ad_gpo_access_send/recv: provides client-side GPO processing
 *
 * This file also implements the following pairs of *private* functions (which
 * are used by the public functions):
 *   ad_gpo_process_som_send/recv: populate list of gp_som objects
 *   ad_gpo_process_gpo_send/recv: populate list of gp_gpo objects
 *   ad_gpo_process_cse_send/recv: retrieve policy file data
 */

#include <ctype.h>
#include <security/pam_modules.h>
#include <syslog.h>
#include <fcntl.h>
#include <ini_configobj.h>
#include "util/util.h"
#include "util/strtonum.h"
#include "util/child_common.h"
#include "providers/data_provider.h"
#include "providers/backend.h"
#include "providers/ad/ad_access.h"
#include "providers/ad/ad_common.h"
#include "providers/ad/ad_domain_info.h"
#include "providers/ad/ad_gpo.h"
#include "providers/ldap/sdap_access.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_idmap.h"
#include "util/util_sss_idmap.h"
#include "util/sss_chain_id.h"
#include <ndr.h>
#include <gen_ndr/security.h>

/* == gpo-ldap constants =================================================== */

#define AD_AT_DN "distinguishedName"
#define AD_AT_UAC "userAccountControl"
#define AD_AT_SAMACCOUNTNAME "sAMAccountName"
#define AD_AT_CONFIG_NC "configurationNamingContext"
#define AD_AT_GPLINK "gPLink"
#define AD_AT_GPOPTIONS "gpOptions"
#define AD_AT_NT_SEC_DESC "nTSecurityDescriptor"
#define AD_AT_CN "cn"
#define AD_AT_FILE_SYS_PATH "gPCFileSysPath"
#define AD_AT_MACHINE_EXT_NAMES "gPCMachineExtensionNames"
#define AD_AT_FUNC_VERSION "gPCFunctionalityVersion"
#define AD_AT_FLAGS "flags"
#define AD_AT_SID "objectSid"

#define UAC_WORKSTATION_TRUST_ACCOUNT 0x00001000
#define UAC_SERVER_TRUST_ACCOUNT 0x00002000
#define AD_AGP_GUID "edacfd8f-ffb3-11d1-b41d-00a0c968f939"
#define AD_AUTHENTICATED_USERS_SID "S-1-5-11"

/* == gpo-smb constants ==================================================== */

#define SMB_STANDARD_URI "smb://"
#define BUFSIZE 65536

#define RIGHTS_SECTION "Privilege Rights"
#define ALLOW_LOGON_INTERACTIVE "SeInteractiveLogonRight"
#define DENY_LOGON_INTERACTIVE "SeDenyInteractiveLogonRight"
#define ALLOW_LOGON_REMOTE_INTERACTIVE "SeRemoteInteractiveLogonRight"
#define DENY_LOGON_REMOTE_INTERACTIVE "SeDenyRemoteInteractiveLogonRight"
#define ALLOW_LOGON_NETWORK "SeNetworkLogonRight"
#define DENY_LOGON_NETWORK "SeDenyNetworkLogonRight"
#define ALLOW_LOGON_BATCH "SeBatchLogonRight"
#define DENY_LOGON_BATCH "SeDenyBatchLogonRight"
#define ALLOW_LOGON_SERVICE "SeServiceLogonRight"
#define DENY_LOGON_SERVICE "SeDenyServiceLogonRight"

#define GP_EXT_GUID_SECURITY "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"
#define GP_EXT_GUID_SECURITY_SUFFIX "/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf"

#ifndef SSSD_LIBEXEC_PATH
#error "SSSD_LIBEXEC_PATH not defined"
#else
#define GPO_CHILD SSSD_LIBEXEC_PATH"/gpo_child"
#endif

#define GPO_CHILD_LOG_FILE "gpo_child"

/* If INI_PARSE_IGNORE_NON_KVP is not defined, use 0 (no effect) */
#ifndef INI_PARSE_IGNORE_NON_KVP
#define INI_PARSE_IGNORE_NON_KVP 0
#warning INI_PARSE_IGNORE_NON_KVP not defined.
#endif

/* == common data structures and declarations ============================= */

struct gp_som {
    const char *som_dn;
    struct gp_gplink **gplink_list;
    int num_gplinks;
};

struct gp_gplink {
    const char *gpo_dn;
    bool enforced;
};

struct gp_gpo {
    struct security_descriptor *gpo_sd;
    const char *gpo_dn;
    const char *gpo_guid;
    const char *smb_server;
    const char *smb_share;
    const char *smb_path;
    const char **gpo_cse_guids;
    int num_gpo_cse_guids;
    int gpo_func_version;
    int gpo_flags;
    bool send_to_child;
    const char *policy_filename;
};

enum ace_eval_agp_status {
    AD_GPO_ACE_DENIED,
    AD_GPO_ACE_ALLOWED,
    AD_GPO_ACE_NEUTRAL
};

struct tevent_req *ad_gpo_process_som_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct sdap_id_conn_ctx *conn,
                                           struct ldb_context *ldb_ctx,
                                           struct sdap_id_op *sdap_op,
                                           struct sdap_options *opts,
                                           struct dp_option *ad_options,
                                           int timeout,
                                           const char *target_dn,
                                           const char *domain_name);
int ad_gpo_process_som_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            struct gp_som ***som_list);

struct tevent_req *
ad_gpo_process_gpo_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct sdap_id_op *sdap_op,
                        struct sdap_options *opts,
                        char *server_hostname,
                        struct sss_domain_info *host_domain,
                        struct ad_access_ctx *access_ctx,
                        int timeout,
                        struct gp_som **som_list);
int ad_gpo_process_gpo_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            struct gp_gpo ***candidate_gpos,
                            int *num_candidate_gpos);

struct tevent_req *ad_gpo_process_cse_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           bool send_to_child,
                                           struct sss_domain_info *domain,
                                           const char *gpo_guid,
                                           const char *smb_server,
                                           const char *smb_share,
                                           const char *smb_path,
                                           const char *smb_cse_suffix,
                                           int cached_gpt_version,
                                           int gpo_timeout_option);

int ad_gpo_process_cse_recv(struct tevent_req *req);

/* == ad_gpo_parse_map_options and helpers ==================================*/

#define GPO_LOGIN "login"
#define GPO_SU "su"
#define GPO_SU_L "su-l"
#define GPO_GDM_FINGERPRINT "gdm-fingerprint"
#define GPO_GDM_PASSWORD "gdm-password"
#define GPO_GDM_SMARTCARD "gdm-smartcard"
#define GPO_KDM "kdm"
#define GPO_LIGHTDM "lightdm"
#define GPO_LXDM "lxdm"
#define GPO_SDDM "sddm"
#define GPO_UNITY "unity"
#define GPO_XDM "xdm"
#define GPO_SSHD "sshd"
#define GPO_FTP "ftp"
#define GPO_SAMBA "samba"
#ifdef HAVE_DEBIAN
#define GPO_CROND "cron"
#else
#define GPO_CROND "crond"
#endif
#define GPO_POLKIT "polkit-1"
#define GPO_SUDO "sudo"
#define GPO_SUDO_I "sudo-i"
#define GPO_SYSTEMD_USER "systemd-user"
#define GPO_COCKPIT "cockpit"

struct gpo_map_option_entry {
    enum gpo_map_type gpo_map_type;
    enum ad_basic_opt ad_basic_opt;
    const char **gpo_map_defaults;
    const char *allow_key;
    const char *deny_key;
};

const char *gpo_map_interactive_defaults[] =
    {GPO_LOGIN, GPO_SU, GPO_SU_L,
     GPO_GDM_FINGERPRINT, GPO_GDM_PASSWORD, GPO_GDM_SMARTCARD, GPO_KDM,
     GPO_LIGHTDM, GPO_LXDM, GPO_SDDM, GPO_UNITY, GPO_XDM, NULL};
const char *gpo_map_remote_interactive_defaults[] = {GPO_SSHD, GPO_COCKPIT,
                                                     NULL};
const char *gpo_map_network_defaults[] = {GPO_FTP, GPO_SAMBA, NULL};
const char *gpo_map_batch_defaults[] = {GPO_CROND, NULL};
const char *gpo_map_service_defaults[] = {NULL};
const char *gpo_map_permit_defaults[] = {GPO_POLKIT,
                                         GPO_SUDO, GPO_SUDO_I,
                                         GPO_SYSTEMD_USER,  NULL};
const char *gpo_map_deny_defaults[] = {NULL};

struct gpo_map_option_entry gpo_map_option_entries[] = {
    {GPO_MAP_INTERACTIVE, AD_GPO_MAP_INTERACTIVE, gpo_map_interactive_defaults,
     ALLOW_LOGON_INTERACTIVE, DENY_LOGON_INTERACTIVE},
    {GPO_MAP_REMOTE_INTERACTIVE, AD_GPO_MAP_REMOTE_INTERACTIVE,
     gpo_map_remote_interactive_defaults,
     ALLOW_LOGON_REMOTE_INTERACTIVE, DENY_LOGON_REMOTE_INTERACTIVE},
    {GPO_MAP_NETWORK, AD_GPO_MAP_NETWORK, gpo_map_network_defaults,
     ALLOW_LOGON_NETWORK, DENY_LOGON_NETWORK},
    {GPO_MAP_BATCH, AD_GPO_MAP_BATCH, gpo_map_batch_defaults,
     ALLOW_LOGON_BATCH, DENY_LOGON_BATCH},
    {GPO_MAP_SERVICE, AD_GPO_MAP_SERVICE, gpo_map_service_defaults,
     ALLOW_LOGON_SERVICE, DENY_LOGON_SERVICE},
    {GPO_MAP_PERMIT, AD_GPO_MAP_PERMIT, gpo_map_permit_defaults, NULL, NULL},
    {GPO_MAP_DENY, AD_GPO_MAP_DENY, gpo_map_deny_defaults, NULL, NULL},
};

static const char* gpo_map_type_string(int gpo_map_type)
{
    switch(gpo_map_type) {
    case GPO_MAP_INTERACTIVE:        return "Interactive";
    case GPO_MAP_REMOTE_INTERACTIVE: return "Remote Interactive";
    case GPO_MAP_NETWORK:            return "Network";
    case GPO_MAP_BATCH:              return "Batch";
    case GPO_MAP_SERVICE:            return "Service";
    case GPO_MAP_PERMIT:             return "Permitted";
    case GPO_MAP_DENY:               return "Denied";
    }
    return "-unknown-";  /* this helper is only used in logs */
}

static inline bool
ad_gpo_service_in_list(char **list, size_t nlist, const char *str)
{
    size_t i;

    for (i = 0; i < nlist; i++) {
        if (strcasecmp(list[i], str) == 0) {
            break;
        }
    }

    return (i < nlist) ? true : false;
}

errno_t
ad_gpo_parse_map_option_helper(enum gpo_map_type gpo_map_type,
                               hash_key_t key,
                               hash_table_t *options_table)
{
    hash_value_t val;
    int hret;
    int ret;

    hret = hash_lookup(options_table, &key, &val);
    if (hret != HASH_SUCCESS && hret != HASH_ERROR_KEY_NOT_FOUND) {
        DEBUG(SSSDBG_OP_FAILURE, "Error checking hash table: [%s]\n",
              hash_error_string(hret));
        ret = EINVAL;
        goto done;
    } else if (hret == HASH_SUCCESS) {
        /* handle unexpected case where mapping for key already exists */
        if (val.i == gpo_map_type) {
            /* mapping for key exists for same map type; no error */
            DEBUG(SSSDBG_TRACE_FUNC,
                  "PAM service %s maps to %s multiple times\n", key.str,
                  gpo_map_type_string(gpo_map_type));
            ret = EOK;
        } else {
            /* mapping for key exists for different map type; error! */
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Configuration error: PAM service %s maps to both %s and "
                  "%s. If you are changing the default mappings of Group "
                  "Policy rules to PAM services using one of the ad_gpo_map_*"
                  " options make sure that the PAM service you add to one map "
                  "using the '+service' syntax is not already present in "
                  "another map by default (if it is then remove it from the "
                  "other map by using the '-service' syntax. Check manual "
                  "pages 'man sssd-ad' for details).\n", key.str,
                  gpo_map_type_string(val.i), gpo_map_type_string(gpo_map_type));
            sss_log(SSS_LOG_ERR,
                  "Configuration error: PAM service %s maps to both %s and "
                  "%s. If you are changing the default mappings of Group "
                  "Policy rules to PAM services using one of the ad_gpo_map_*"
                  " options make sure that the PAM service you add to one map "
                  "using the '+service' syntax is not already present in "
                  "another map by default (if it is then remove it from the "
                  "other map by using the '-service' syntax. Check manual "
                  "pages 'man sssd-ad' for details).\n", key.str,
                  gpo_map_type_string(val.i), gpo_map_type_string(gpo_map_type));
            ret = EINVAL;
        }
        goto done;
    } else {
        /* handle expected case where mapping for key doesn't already exist */
        val.type = HASH_VALUE_INT;
        val.i = gpo_map_type;

        hret = hash_enter(options_table, &key, &val);
        if (hret != HASH_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "Error checking hash table: [%s]\n",
                  hash_error_string(hret));
            ret = EIO;
            goto done;
        }
        ret = EOK;
    }

done:
    return ret;
}

errno_t
ad_gpo_parse_map_option(TALLOC_CTX *mem_ctx,
                        enum gpo_map_type gpo_map_type,
                        hash_table_t *options_table,
                        char *conf_str,
                        const char **defaults)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    char **conf_list = NULL;
    int conf_list_size = 0;
    char **add_list = NULL;
    char **remove_list = NULL;
    int ai = 0, ri = 0;
    int i;
    hash_key_t key;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "gpo_map_type: %s\n",
          gpo_map_type_string(gpo_map_type));

    if (conf_str) {
        ret = split_on_separator(tmp_ctx, conf_str, ',', true, true,
                                 &conf_list, &conf_list_size);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot parse list of service names %s: %d\n", conf_str, ret);
            ret = EINVAL;
            goto done;
        }

        add_list = talloc_zero_array(tmp_ctx, char *, conf_list_size);
        remove_list = talloc_zero_array(tmp_ctx, char *, conf_list_size);
        if (add_list == NULL || remove_list == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    for (i = 0; i < conf_list_size; i++) {
        switch (conf_list[i][0]) {
        case '+':
            add_list[ai] = conf_list[i] + 1;
            ai++;
            continue;
        case '-':
            remove_list[ri] = conf_list[i] + 1;
            ri++;
            continue;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "ad_gpo_map values must start with"
                  "either '+' (for adding service) or '-' (for removing service), "
                  "got '%s'\n",
                  conf_list[i]);
            ret = EINVAL;
            goto done;
        }
    }

    /* Start by adding explicitly added services ('+') to hashtable */
    for (i = 0; i < ai; i++) {
        /* if the service is explicitly configured to be removed, skip it */
        if (ad_gpo_service_in_list(remove_list, ri, add_list[i])) {
            continue;
        }

        key.type = HASH_KEY_STRING;
        key.str = (char *)add_list[i];

        ret = ad_gpo_parse_map_option_helper(gpo_map_type, key, options_table);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Invalid configuration: %d\n", ret);
            goto done;
        }

        DEBUG(SSSDBG_TRACE_ALL, "Explicitly added service: %s\n", key.str);
    }

    /* Add defaults to hashtable */
    for (i = 0; defaults[i]; i++) {
        /* if the service is explicitly configured to be removed, skip it */
        if (ad_gpo_service_in_list(remove_list, ri, defaults[i])) {
            continue;
        }

        key.type = HASH_KEY_STRING;
        key.str = talloc_strdup(mem_ctx, defaults[i]);

        ret = ad_gpo_parse_map_option_helper(gpo_map_type, key, options_table);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Invalid configuration: %d\n", ret);
            goto done;
        }

        DEBUG(SSSDBG_TRACE_ALL, "Default service (not explicitly removed): %s\n",
              key.str);
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
ad_gpo_parse_map_options(struct ad_access_ctx *access_ctx)
{
    char *gpo_default_right_config;
    enum gpo_map_type gpo_default_right;
    errno_t ret;
    int i;

    for (i = 0; i < GPO_MAP_NUM_OPTS; i++) {

        struct gpo_map_option_entry entry = gpo_map_option_entries[i];

        char *entry_config =  dp_opt_get_string(access_ctx->ad_options,
                                                entry.ad_basic_opt);

        ret = ad_gpo_parse_map_option(access_ctx, entry.gpo_map_type,
                                      access_ctx->gpo_map_options_table,
                                      entry_config, entry.gpo_map_defaults);

        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Invalid configuration: %d\n", ret);
            ret = EINVAL;
            goto fail;
        }
    }

    /* default right (applicable for services without any mapping) */
    gpo_default_right_config =
        dp_opt_get_string(access_ctx->ad_options, AD_GPO_DEFAULT_RIGHT);

    DEBUG(SSSDBG_TRACE_ALL, "gpo_default_right_config: %s\n",
          gpo_default_right_config);

    /* if default right not set in config, set them to DENY */
    if (gpo_default_right_config == NULL) {
        gpo_default_right = GPO_MAP_DENY;
    } else if (strncasecmp(gpo_default_right_config, "interactive",
                           strlen("interactive")) == 0) {
        gpo_default_right = GPO_MAP_INTERACTIVE;
    } else if (strncasecmp(gpo_default_right_config, "remote_interactive",
                           strlen("remote_interactive")) == 0) {
        gpo_default_right = GPO_MAP_REMOTE_INTERACTIVE;
    } else if (strncasecmp(gpo_default_right_config, "network",
                           strlen("network")) == 0) {
        gpo_default_right = GPO_MAP_NETWORK;
    } else if (strncasecmp(gpo_default_right_config, "batch",
                           strlen("batch")) == 0) {
        gpo_default_right = GPO_MAP_BATCH;
    } else if (strncasecmp(gpo_default_right_config, "service",
                           strlen("service")) == 0) {
        gpo_default_right = GPO_MAP_SERVICE;
    } else if (strncasecmp(gpo_default_right_config, "permit",
                           strlen("permit")) == 0) {
        gpo_default_right = GPO_MAP_PERMIT;
    } else if (strncasecmp(gpo_default_right_config, "deny",
                           strlen("deny")) == 0) {
        gpo_default_right = GPO_MAP_DENY;
    } else {
        ret = EINVAL;
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_ALL, "gpo_default_right: %d\n", gpo_default_right);
    access_ctx->gpo_default_right = gpo_default_right;

fail:
    return ret;
}

/* == ad_gpo_access_send/recv helpers =======================================*/

static bool
ad_gpo_dom_sid_equal(const struct dom_sid *sid1, const struct dom_sid *sid2)
{
    int i;

    if (sid1 == sid2) {
        return true;
    }

    if (!sid1 || !sid2) {
        return false;
    }

    if (sid1->sid_rev_num != sid2->sid_rev_num) {
        return false;
    }

    for (i = 0; i < 6; i++) {
        if (sid1->id_auth[i] != sid2->id_auth[i]) {
            return false;
        }
    }

    if (sid1->num_auths != sid2->num_auths) {
        return false;
    }

    for (i = 0; i < sid1->num_auths; i++) {
        if (sid1->sub_auths[i] != sid2->sub_auths[i]) {
            return false;
        }
    }

    return true;
}

/*
 * This function retrieves the SID of the group with given gid.
 */
static char *
ad_gpo_get_primary_group_sid(TALLOC_CTX *mem_ctx,
                             gid_t gid,
                             struct sss_domain_info *domain,
                             struct sss_idmap_ctx *idmap_ctx)
{
    char *idmap_sid = NULL;
    const char *cache_sid;
    char *result;
    const char *attrs[] = {
        SYSDB_SID_STR,
        NULL
    };
    struct ldb_message *msg;
    int ret;

    if (gid == 0) {
        return NULL;
    }

    ret = sss_idmap_unix_to_sid(idmap_ctx, gid, &idmap_sid);
    if (ret == EOK) {
        result = talloc_strdup(mem_ctx, idmap_sid);
        sss_idmap_free_sid(idmap_ctx, idmap_sid);
        if (result == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Out of memory while getting SID of the group\n");
        }
        return result;
    }

    if (ret == IDMAP_EXTERNAL) {
        /* no ID mapping in this domain, search for the group object and get sid there */
        ret = sysdb_search_group_by_gid(mem_ctx, domain, gid, attrs, &msg);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Search for group '%"SPRIgid"' failded with error '%d'\n", gid, ret);
            return NULL;
        }

        cache_sid = ldb_msg_find_attr_as_string(msg, SYSDB_SID_STR, NULL);
        if (cache_sid == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get SID attribute of the group '%"SPRIgid"'\n", gid);
            return NULL;
        }

        result = talloc_strdup(mem_ctx, cache_sid);
        if (result == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Out of memory while getting group SID\n");
        }
        return result;
    }

    DEBUG(SSSDBG_OP_FAILURE, "Failed to get SID of primary the group '%"SPRIgid"'\n", gid);
    return NULL;
}

/*
 * This function retrieves the SIDs corresponding to the input user and returns
 * the user_sid, group_sids, and group_size in their respective output params.
 *
 * Note: since authentication must complete successfully before the
 * gpo access checks are called, we can safely assume that the user/computer
 * has been authenticated. As such, this function always adds the
 * AD_AUTHENTICATED_USERS_SID to the group_sids.
 */
static errno_t
ad_gpo_get_sids(TALLOC_CTX *mem_ctx,
                const char *user,
                struct sss_domain_info *domain,
                struct sss_idmap_ctx *idmap_ctx,
                const char **_user_sid,
                const char ***_group_sids,
                int *_group_size)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_result *res;
    int ret = 0;
    int i = 0;
    int num_group_sids = 0;
    const char *user_sid = NULL;
    const char *group_sid = NULL;
    const char **group_sids = NULL;
    gid_t orig_gid = 0;
    char *orig_gid_sid = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* first result from sysdb_initgroups is user_sid; rest are group_sids */
    ret = sysdb_initgroups(tmp_ctx, domain, user, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_initgroups failed: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (res->count == 0) {
        ret = ENOENT;
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_initgroups returned empty result\n");
        goto done;
    }

    user_sid = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SID_STR, NULL);

    /* if there is origPrimaryGroupGidNumber, it's SID must be added to list */
    orig_gid = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                           SYSDB_PRIMARY_GROUP_GIDNUM,
                                           0);
    orig_gid_sid = ad_gpo_get_primary_group_sid(tmp_ctx,
                                                orig_gid,
                                                domain,
                                                idmap_ctx);
    DEBUG(SSSDBG_TRACE_INTERNAL, "SID of the primary group with gid '%"SPRIgid"' is '%s'\n", orig_gid, orig_gid_sid);

    num_group_sids = (res->count) - 1;

    /* include space for AD_AUTHENTICATED_USERS_SID, original GID sid and NULL */
    group_sids = talloc_array(tmp_ctx, const char *, num_group_sids + 3);
    if (group_sids == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_group_sids; i++) {
        group_sid = ldb_msg_find_attr_as_string(res->msgs[i+1],
                                                SYSDB_SID_STR, NULL);
        if (group_sid == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Missing SID for cache entry [%s].\n",
                  ldb_dn_get_linearized(res->msgs[i+1]->dn));
            ret = EINVAL;
            goto done;
        }

        group_sids[i] = talloc_steal(group_sids, group_sid);
        if (group_sids[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }
    group_sids[i++] = talloc_strdup(group_sids, AD_AUTHENTICATED_USERS_SID);
    if (orig_gid_sid != NULL) {
        group_sids[i++] = orig_gid_sid;
    }
    group_sids[i] = NULL;

    *_group_size = i;
    *_group_sids = talloc_steal(mem_ctx, group_sids);
    *_user_sid = talloc_steal(mem_ctx, user_sid);
    ret = EOK;

 done:
    talloc_free(tmp_ctx);
    return ret;
}

/*
 * This function determines whether the input ace_dom_sid matches any of the
 * client's SIDs. The boolean result is assigned to the _included output param.
 */
static errno_t
ad_gpo_ace_includes_client_sid(const char *user_sid,
                               const char *host_sid,
                               const char **group_sids,
                               int group_size,
                               const char **host_group_sids,
                               int host_group_size,
                               struct dom_sid ace_dom_sid,
                               struct sss_idmap_ctx *idmap_ctx,
                               bool *_included)
{
    int i = 0;
    struct dom_sid *user_dom_sid;
    struct dom_sid *host_dom_sid;
    struct dom_sid *group_dom_sid;
    enum idmap_error_code err;
    bool included = false;

    err = sss_idmap_sid_to_smb_sid(idmap_ctx, user_sid, &user_dom_sid);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_idmap_sid_to_smb_sid() failed for user_sid '%s': %d\n",
              user_sid, err);
        return EFAULT;
    }

    included = ad_gpo_dom_sid_equal(&ace_dom_sid, user_dom_sid);
    sss_idmap_free_smb_sid(idmap_ctx, user_dom_sid);
    if (included) {
        *_included = true;
        return EOK;
    }

    err = sss_idmap_sid_to_smb_sid(idmap_ctx, host_sid, &host_dom_sid);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_idmap_sid_to_smb_sid() failed for host_sid '%s': %d\n",
              host_sid, err);
        return EFAULT;
    }

    included = ad_gpo_dom_sid_equal(&ace_dom_sid, host_dom_sid);
    sss_idmap_free_smb_sid(idmap_ctx, host_dom_sid);
    if (included) {
        *_included = true;
        return EOK;
    }

    for (i = 0; i < group_size; i++) {
        err = sss_idmap_sid_to_smb_sid(idmap_ctx, group_sids[i], &group_dom_sid);
        if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_idmap_sid_to_smb_sid() failed for group_sid '%s': %d\n",
              group_sids[i], err);
            return EFAULT;
        }
        included = ad_gpo_dom_sid_equal(&ace_dom_sid, group_dom_sid);
        sss_idmap_free_smb_sid(idmap_ctx, group_dom_sid);
        if (included) {
            *_included = true;
            return EOK;
        }
    }

    for (i = 0; i < host_group_size; i++) {
        err = sss_idmap_sid_to_smb_sid(idmap_ctx, host_group_sids[i], &group_dom_sid);
        if (err != IDMAP_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sss_idmap_sid_to_smb_sid() failed for group_sid '%s': %d\n",
                  group_sids[i], err);
            return EFAULT;
        }
        included = ad_gpo_dom_sid_equal(&ace_dom_sid, group_dom_sid);
        sss_idmap_free_smb_sid(idmap_ctx, group_dom_sid);
        if (included) {
            *_included = true;
            return EOK;
        }
    }

    *_included = false;
    return EOK;
}

/*
 * This function determines whether use of the extended right named
 * "ApplyGroupPolicy" (AGP) is allowed for the GPO, by comparing the
 * specified user_sid and group_sids against the passed access control
 * entry (ACE).
 * This function returns ALLOWED, DENIED, or NEUTRAL depending on whether
 * the ACE explicitly allows, explicitly denies, or does neither.
 *
 * Notes:
 * (1) Abbreviation 'M' used in the evaluation algorithm stands for
 * "access_mask", which represents the set of access rights associated with
 * the passed ACE. The access right of interest to the GPO code is
 * RIGHT_DS_CONTROL_ACCESS, which serves as a container for all control access
 * rights. The specific control access right is identified by a GUID in the
 * ACE's ObjectType. In our case, this is the GUID corresponding to AGP.
 * (2) ACE that require an evaluation algorithm different from [MS-ADTS]
 * 5.1.3.3.4, e. g. RIGHT_DS_CONTROL_ACCESS (CR) is not present in M, are
 * ignored.
 *
 * The ACE evaluation algorithm is specified in [MS-ADTS] 5.1.3.3.4:
 * Evaluate the DACL by examining each ACE in sequence, starting with the first
 * ACE. Perform the following sequence of actions for each ACE in the order as
 * shown:
 * 1. If the "Inherit Only" (IO) flag is set in the ACE, skip the ACE.
 * 2. If the SID in the ACE does not match any SID in the requester's
 *    security context, skip the ACE.
 * 3. If the ACE type is "Object Access Allowed", the access right
 *    RIGHT_DS_CONTROL_ACCESS (CR) is present in M, and the ObjectType
 *    field in the ACE is not present, then grant the requested control
 *    access right. Stop any further access checks.
 * 4. If the ACE type is "Object Access Allowed" the access right
 *    RIGHT_DS_CONTROL_ACCESS (CR) is present in M, and the ObjectType
 *    field in the ACE contains a GUID value equal to AGP, then grant
 *    the requested control access right. Stop any further access checks.
 * 5. If the ACE type is "Object Access Denied", the access right
 *    RIGHT_DS_CONTROL_ACCESS (CR) is present in M, and the ObjectType
 *    field in the ACE is not present, then deny the requested control
 *    access right. Stop any further access checks.
 * 6. If the ACE type is "Object Access Denied" the access right
 *    RIGHT_DS_CONTROL_ACCESS (CR) is present in M, and the ObjectType
 *    field in the ACE contains a GUID value equal to AGP, then deny
 *    the requested control access right. Stop any further access checks.
 */
static enum ace_eval_agp_status ad_gpo_evaluate_ace(struct security_ace *ace,
                                                    struct sss_idmap_ctx *idmap_ctx,
                                                    const char *user_sid,
                                                    const char *host_sid,
                                                    const char **group_sids,
                                                    int group_size,
                                                    const char **host_group_sids,
                                                    int host_group_size)
{
    bool included = false;
    int ret = 0;
    struct security_ace_object object;
    struct GUID ext_right_agp_guid;

    if (ace->flags & SEC_ACE_FLAG_INHERIT_ONLY) {
        return AD_GPO_ACE_NEUTRAL;
    }

    ret = ad_gpo_ace_includes_client_sid(user_sid, host_sid, group_sids,
                                         group_size, host_group_sids,
                                         host_group_size, ace->trustee,
                                         idmap_ctx, &included);
    if (ret != EOK) {
        return AD_GPO_ACE_DENIED;
    }

    if (!included) {
        return AD_GPO_ACE_NEUTRAL;
    }

    if (ace->access_mask & SEC_ADS_CONTROL_ACCESS) {
        object = ace->object.object;
        if (object.flags & SEC_ACE_OBJECT_TYPE_PRESENT) {
            GUID_from_string(AD_AGP_GUID, &ext_right_agp_guid);
            if (!GUID_equal(&object.type.type, &ext_right_agp_guid)) {
                return AD_GPO_ACE_NEUTRAL;
            }
        }
        if (ace->type == SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT) {
            return AD_GPO_ACE_ALLOWED;
        } else if (ace->type == SEC_ACE_TYPE_ACCESS_DENIED_OBJECT) {
            return AD_GPO_ACE_DENIED;
        }
    }

    return AD_GPO_ACE_NEUTRAL;
}

/*
 * This function evaluates, which standard access rights the passed access
 * control entry (ACE) allows or denies for the entire GPO.
 *
 * Notes:
 * (1) Abbreviation 'M' used in the evaluation algorithm stands for
 * "access_mask", which represents the set of access rights associated with
 * the passed ACE.
 * (2) Abbreviation 'G' used in the evaluation algorithm stands for
 * "granted rights", which represents the set of access rights, that
 * have already been granted by previously evaluated ACEs.
 * (3) Abbreviation 'D' used in the evaluation algorithm stands for
 * "denied rights", which represents the set of access rights, that
 * have already been explicitly denied by previously evaluated ACEs.
 *
 * The simple ACE evaluation algorithm is specified in [MS-ADTS] 5.1.3.3.2:
 * Evaluate the DACL by examining each ACE in sequence, starting with the first
 * ACE. Perform the following sequence of actions for each ACE in the order as
 * shown:
 * 1. If the "Inherit Only" (IO) flag is set in the ACE, skip the ACE.
 * 2. If the SID in the ACE does not match any SID in the requester's
 *    security context, skip the ACE.
 * 3. If the ACE type is "Access Denied" and the access rights in M
 *    are not in G, then add the rights in M to D.
 * 4. If the ACE type is "Access Allowed" and the access rights in M
 *    are not in D, then add the rights in M to G.
 */
static errno_t ad_gpo_simple_evaluate_ace(struct security_ace *ace,
                                          struct sss_idmap_ctx *idmap_ctx,
                                          const char *user_sid,
                                          const char *host_sid,
                                          const char **group_sids,
                                          int group_size,
                                          const char **host_group_sids,
                                          int host_group_size,
                                          uint32_t *_gpo_access_granted_status,
                                          uint32_t *_gpo_access_denied_status)
{
    bool included = false;
    uint32_t filtered_access_rights = 0;
    int ret = 0;

    if (ace->flags & SEC_ACE_FLAG_INHERIT_ONLY) {
        return EOK;
    }

    ret = ad_gpo_ace_includes_client_sid(user_sid, host_sid, group_sids, group_size,
                                         host_group_sids, host_group_size,
                                         ace->trustee, idmap_ctx, &included);

    if (ret != EOK || !included) {
        return ret;
    }

    if (ace->type == SEC_ACE_TYPE_ACCESS_DENIED) {
        filtered_access_rights = ace->access_mask & ~*_gpo_access_granted_status;
        *_gpo_access_denied_status |= filtered_access_rights;
    } else if (ace->type == SEC_ACE_TYPE_ACCESS_ALLOWED) {
        filtered_access_rights = ace->access_mask & ~*_gpo_access_denied_status;
        *_gpo_access_granted_status |= filtered_access_rights;
    }

    return ret;
}


/*
 * This function extracts the GPO's DACL (discretionary access control list)
 * from the GPO's specified security descriptor, and determines whether
 * the GPO is applicable to the policy target, by comparing the specified
 * user_sid and group_sids against each access control entry (ACE) in the DACL.
 * The GPO is only applicable to the target, if the requester has been granted
 * read access (RIGHT_DS_READ_PROPERTY) to the properties of the GPO and
 * control access (RIGHT_DS_CONTROL_ACCESS) to apply the GPO (AGP).
 * The required read and control access rights for a particular trustee are
 * usually located in different ACEs, i.e. one ACE for control of read access
 * and one for control access.
 * If it comes to the end of the DACL, and the required access is still not
 * explicitly allowed or denied, SSSD denies access to the object as specified
 * in [MS-ADTS] 5.1.3.1.
 */
static errno_t ad_gpo_evaluate_dacl(struct security_acl *dacl,
                                    struct sss_idmap_ctx *idmap_ctx,
                                    const char *user_sid,
                                    const char *host_sid,
                                    const char **group_sids,
                                    int group_size,
                                    const char **host_group_sids,
                                    int host_group_size,
                                    bool *_dacl_access_allowed)
{
    uint32_t num_aces = 0;
    uint32_t access_granted_status = 0;
    uint32_t access_denied_status = 0;
    enum ace_eval_agp_status ace_status;
    struct security_ace *ace = NULL;
    int i = 0;
    int ret = 0;
    enum idmap_error_code err;
    char *trustee_dom_sid_str = NULL;

    num_aces = dacl->num_aces;

    /*
     * [MS-ADTS] 5.1.3.3.2. and 5.1.3.3.4:
     * If the DACL does not have any ACE, then deny the requester the
     * requested control access right.
     */
    if (num_aces == 0) {
        *_dacl_access_allowed = false;
        return EOK;
    }

    /*
     * [MS-GOPD] 2.4:
     * To process a policy that applies to a Group Policy client, the core
     * Group Policy engine must be able to read the policy data from the
     * directory service so that the policy settings can be applied to the
     * Group Policy client or the interactive user.
     */
    for (i = 0; i < dacl->num_aces; i++) {
        ace = &dacl->aces[i];

        ret = ad_gpo_simple_evaluate_ace(ace, idmap_ctx, user_sid, host_sid,
                                         group_sids, group_size,
                                         host_group_sids, host_group_size,
                                         &access_granted_status,
                                         &access_denied_status);

        if (ret != EOK) {
            err = sss_idmap_smb_sid_to_sid(idmap_ctx, &ace->trustee,
                                           &trustee_dom_sid_str);
            if (err != IDMAP_SUCCESS) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sss_idmap_smb_sid_to_sid failed.\n");
                return EFAULT;
            }

            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Could not determine if ACE is applicable; "
                  " Trustee: %s\n", trustee_dom_sid_str);
            sss_idmap_free_sid(idmap_ctx, trustee_dom_sid_str);
            trustee_dom_sid_str = NULL;
            continue;
        }
    }

    for (i = 0; i < dacl->num_aces; i ++) {
        ace = &dacl->aces[i];

        err = sss_idmap_smb_sid_to_sid(idmap_ctx, &ace->trustee,
                                       &trustee_dom_sid_str);
        if (err != IDMAP_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_idmap_smb_sid_to_sid failed.\n");
            return EFAULT;
        }

        ace_status = ad_gpo_evaluate_ace(ace, idmap_ctx, user_sid, host_sid,
                                         group_sids, group_size,
                                         host_group_sids, host_group_size);

        switch (ace_status) {
        case AD_GPO_ACE_NEUTRAL:
            break;
        case AD_GPO_ACE_ALLOWED:
            if (access_granted_status & SEC_ADS_READ_PROP) {
                *_dacl_access_allowed = true;
                sss_idmap_free_sid(idmap_ctx, trustee_dom_sid_str);
                return EOK;
            } else {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "GPO read properties access denied (security); "
                      " Trustee: %s\n", trustee_dom_sid_str);
                break;
            }
        case AD_GPO_ACE_DENIED:
            if (access_granted_status & SEC_ADS_READ_PROP) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "GPO denied (security); "
                      " Trustee: %s\n", trustee_dom_sid_str);
                sss_idmap_free_sid(idmap_ctx, trustee_dom_sid_str);
                *_dacl_access_allowed = false;
                return EOK;
            } else {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "GPO read properties access denied (security); "
                      " Trustee: %s\n", trustee_dom_sid_str);
                break;
            }
        }
        sss_idmap_free_sid(idmap_ctx, trustee_dom_sid_str);
        trustee_dom_sid_str = NULL;
    }

    if (access_granted_status & SEC_ADS_READ_PROP) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "GPO apply group policy access denied (security)\n");
    }

    *_dacl_access_allowed = false;
    return EOK;
}

/*
 * This function takes candidate_gpos as input, filters out any gpo that is
 * not applicable to the policy target and assigns the result to the
 * _dacl_filtered_gpos output parameter. The filtering algorithm is
 * defined in [MS-GPOL] 3.2.5.1.6
 */
static errno_t
ad_gpo_filter_gpos_by_dacl(TALLOC_CTX *mem_ctx,
                           const char *user,
                           const char *host_fqdn,
                           struct sss_domain_info *domain,
                           struct sss_domain_info *host_domain,
                           struct sss_idmap_ctx *idmap_ctx,
                           struct gp_gpo **candidate_gpos,
                           int num_candidate_gpos,
                           struct gp_gpo ***_dacl_filtered_gpos,
                           int *_num_dacl_filtered_gpos)
{
    TALLOC_CTX *tmp_ctx = NULL;
    int i = 0;
    int ret = 0;
    struct gp_gpo *candidate_gpo = NULL;
    struct security_descriptor *sd = NULL;
    struct security_acl *dacl = NULL;
    const char *user_sid = NULL;
    const char **group_sids = NULL;
    int group_size = 0;
    const char *host_sid = NULL;
    const char **host_group_sids = NULL;
    int host_group_size = 0;
    int gpo_dn_idx = 0;
    bool access_allowed = false;
    struct gp_gpo **dacl_filtered_gpos = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ad_gpo_get_sids(tmp_ctx, user, domain, idmap_ctx, &user_sid,
                          &group_sids, &group_size);
    if (ret != EOK) {
        ret = ERR_NO_SIDS;
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to retrieve SIDs: [%d](%s)\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = ad_gpo_get_sids(tmp_ctx, host_fqdn, host_domain, idmap_ctx, &host_sid,
                          &host_group_sids, &host_group_size);
    if (ret != EOK) {
        ret = ERR_NO_SIDS;
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to retrieve host SIDs: [%d](%s)\n", ret, sss_strerror(ret));
        goto done;
    }

    dacl_filtered_gpos = talloc_array(tmp_ctx,
                                 struct gp_gpo *,
                                 num_candidate_gpos + 1);

    if (dacl_filtered_gpos == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_candidate_gpos; i++) {

        access_allowed = false;
        candidate_gpo = candidate_gpos[i];

        DEBUG(SSSDBG_TRACE_FUNC, "examining dacl candidate_gpo_guid:%s\n",
              candidate_gpo->gpo_guid);

        /* gpo_func_version must be set to version 2 */
        if (candidate_gpo->gpo_func_version != 2) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "GPO not applicable to target per security filtering: "
                  "gPCFunctionalityVersion is not 2\n");
            continue;
        }

        sd = candidate_gpo->gpo_sd;
        if (sd == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Security descriptor is missing\n");
            ret = EINVAL;
            goto done;
        }

        dacl = candidate_gpo->gpo_sd->dacl;

        /* gpo_flags value of 2 means that GPO's computer portion is disabled */
        if (candidate_gpo->gpo_flags == 2) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "GPO not applicable to target per security filtering: "
                  "GPO's computer portion is disabled\n");
            continue;
        }

        if ((sd->type & SEC_DESC_DACL_PRESENT) && (dacl != NULL)) {
            ret = ad_gpo_evaluate_dacl(dacl, idmap_ctx, user_sid, host_sid,
                                       group_sids, group_size, host_group_sids,
                                       host_group_size, &access_allowed);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Could not determine if GPO is applicable\n");
                continue;
            }
        } else {
            /*
             * [MS-ADTS] 5.1.3.3.4:
             * If the security descriptor has no DACL or its "DACL Present" bit
             * is not set, then grant requester the requested control access right.
             */

            DEBUG(SSSDBG_TRACE_ALL, "DACL is not present\n");
            access_allowed = true;
        }

        if (access_allowed) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "GPO applicable to target per security filtering\n");
            dacl_filtered_gpos[gpo_dn_idx] = talloc_steal(dacl_filtered_gpos,
                                                          candidate_gpo);
            gpo_dn_idx++;
        } else {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "GPO not applicable to target per security filtering: "
                  "result of DACL evaluation\n");
            continue;
        }
    }

    dacl_filtered_gpos[gpo_dn_idx] = NULL;

    *_dacl_filtered_gpos = talloc_steal(mem_ctx, dacl_filtered_gpos);
    *_num_dacl_filtered_gpos = gpo_dn_idx;

    ret = EOK;

 done:
    talloc_free(tmp_ctx);
    return ret;
}

/*
 * This function determines whether the input cse_guid matches any of the input
 * gpo_cse_guids. The boolean result is assigned to the _included output param.
 */
static bool
ad_gpo_includes_cse_guid(const char *cse_guid,
                         const char **gpo_cse_guids,
                         int num_gpo_cse_guids)
{
    int i = 0;
    const char *gpo_cse_guid = NULL;

    for (i = 0; i < num_gpo_cse_guids; i++) {
        gpo_cse_guid = gpo_cse_guids[i];
        if (strcmp(gpo_cse_guid, cse_guid) == 0) {
            return true;
        }
    }

    return false;
}

/*
 * This function takes an input dacl_filtered_gpos list, filters out any gpo
 * that does not contain the input cse_guid, and assigns the result to the
 * _cse_filtered_gpos output parameter.
 */
static errno_t
ad_gpo_filter_gpos_by_cse_guid(TALLOC_CTX *mem_ctx,
                               const char *cse_guid,
                               struct gp_gpo **dacl_filtered_gpos,
                               int num_dacl_filtered_gpos,
                               struct gp_gpo ***_cse_filtered_gpos,
                               int *_num_cse_filtered_gpos)
{
    TALLOC_CTX *tmp_ctx = NULL;
    int i = 0;
    int ret = 0;
    struct gp_gpo *dacl_filtered_gpo = NULL;
    int gpo_dn_idx = 0;
    struct gp_gpo **cse_filtered_gpos = NULL;
    bool included;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    cse_filtered_gpos = talloc_array(tmp_ctx,
                                     struct gp_gpo *,
                                     num_dacl_filtered_gpos + 1);
    if (cse_filtered_gpos == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_dacl_filtered_gpos; i++) {

        dacl_filtered_gpo = dacl_filtered_gpos[i];

        DEBUG(SSSDBG_TRACE_ALL, "examining cse candidate_gpo_guid: %s\n",
              dacl_filtered_gpo->gpo_guid);

        included = ad_gpo_includes_cse_guid(cse_guid,
                                            dacl_filtered_gpo->gpo_cse_guids,
                                            dacl_filtered_gpo->num_gpo_cse_guids);

        if (included) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "GPO applicable to target per cse_guid filtering\n");
            cse_filtered_gpos[gpo_dn_idx] = talloc_steal(cse_filtered_gpos,
                                                         dacl_filtered_gpo);
            dacl_filtered_gpos[i] = NULL;
            gpo_dn_idx++;
        } else {
            DEBUG(SSSDBG_TRACE_ALL,
                  "GPO not applicable to target per cse_guid filtering\n");
            continue;
        }
    }

    cse_filtered_gpos[gpo_dn_idx] = NULL;

    *_cse_filtered_gpos = talloc_steal(mem_ctx, cse_filtered_gpos);
    *_num_cse_filtered_gpos = gpo_dn_idx;

    ret = EOK;

 done:
    talloc_free(tmp_ctx);
    return ret;
}

/*
 * This cse-specific function (GP_EXT_GUID_SECURITY) returns a boolean value
 * based on whether the input user_sid or any of the input group_sids appear
 * in the input list of privilege_sids.
 */
static bool
check_rights(char **privilege_sids,
             int privilege_size,
             const char *user_sid,
             const char **group_sids,
             int group_size)
{
    int i, j;

    for (i = 0; i < privilege_size; i++) {
        if (strcmp(user_sid, privilege_sids[i]) == 0) {
            return true;
        }
        for (j = 0; j < group_size; j++) {
            if (strcmp(group_sids[j], privilege_sids[i]) == 0) {
                return true;
            }
        }
    }

    return false;
}

/*
 * This function parses the input ini_config object (which represents
 * the cse-specific filename), and returns the policy_setting_value
 * corresponding to the input policy_setting_key.
 */
static errno_t
ad_gpo_extract_policy_setting(TALLOC_CTX *mem_ctx,
                              struct ini_cfgobj *ini_config,
                              const char *policy_setting_key,
                              char **_policy_setting_value)
{
    struct value_obj *vobj = NULL;
    int ret;
    const char *policy_setting_value;

    ret = ini_get_config_valueobj(RIGHTS_SECTION, policy_setting_key, ini_config,
                                  INI_GET_FIRST_VALUE, &vobj);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ini_get_config_valueobj failed [%d][%s]\n", ret, strerror(ret));
        goto done;
    }
    if (vobj == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "section/name not found: [%s][%s]\n",
              RIGHTS_SECTION, policy_setting_key);
        ret = ENOENT;
        goto done;
    }
    policy_setting_value = ini_get_string_config_value(vobj, &ret);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ini_get_string_config_value failed [%d][%s]\n",
              ret, strerror(ret));
        goto done;
    }

    if (policy_setting_value[0]) {
        *_policy_setting_value = talloc_strdup(mem_ctx, policy_setting_value);
        if (!*_policy_setting_value) {
            ret = ENOMEM;
            goto done;
        }
    } else {
        /* This is an explicitly empty policy setting.
         * We need to remove this from the LDB.
         */
        *_policy_setting_value = NULL;
    }

    ret = EOK;

 done:

    return ret;
}

/*
 * This function parses the cse-specific (GP_EXT_GUID_SECURITY) filename,
 * and stores the allow_key and deny_key of all of the gpo_map_types present
 * in the file (as part of the GPO Result object in the sysdb cache).
 */
static errno_t
ad_gpo_store_policy_settings(struct sss_domain_info *domain,
                             const char *filename)
{
    struct ini_cfgfile *file_ctx = NULL;
    struct ini_cfgobj *ini_config = NULL;
    int ret;
    int i;
    char *allow_value = NULL;
    char *deny_value = NULL;
    const char *empty_val = "NO_SID";
    const char *allow_key = NULL;
    const char *deny_key = NULL;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ini_config_create(&ini_config);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ini_config_create failed [%d][%s]\n", ret, strerror(ret));
        goto done;
    }

    ret = ini_config_file_open(filename, 0, &file_ctx);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ini_config_file_open failed [%d][%s]\n", ret, strerror(ret));
        goto done;
    }

    ret = ini_config_parse(file_ctx, INI_STOP_ON_NONE, 0, 0, ini_config);
    if (ret != 0) {
        int lret;
        char **errors;

        DEBUG(SSSDBG_CRIT_FAILURE,
              "[%s]: ini_config_parse failed [%d][%s]\n",
              filename, ret, strerror(ret));

        /* Now get specific errors if there are any */
        lret = ini_config_get_errors(ini_config, &errors);
        if (lret != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to get specific parse error [%d][%s]\n", lret,
                  strerror(lret));
            goto done;
        }

        for (int a = 0; errors[a]; a++) {
             DEBUG(SSSDBG_CRIT_FAILURE, "%s\n", errors[a]);
        }
        ini_config_free_errors(errors);

        /* Do not 'goto done' here. We will try to parse
         * the GPO file again. */
    }

    if (ret != EOK) {
        /* A problem occurred during parsing. Try again
         * with INI_PARSE_IGNORE_NON_KVP flag */

        ini_config_file_destroy(file_ctx);
        file_ctx = NULL;
        ini_config_destroy(ini_config);
        ini_config = NULL;

        ret = ini_config_file_open(filename, 0, &file_ctx);
        if (ret != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ini_config_file_open failed [%d][%s]\n",
                  ret, strerror(ret));
            goto done;
        }

        ret = ini_config_create(&ini_config);
        if (ret != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ini_config_create failed [%d][%s]\n", ret, strerror(ret));
            goto done;
        }

        ret = ini_config_parse(file_ctx, INI_STOP_ON_NONE, 0,
                               INI_PARSE_IGNORE_NON_KVP, ini_config);
        if (ret != 0) {
            int lret;
            char **errors;

            DEBUG(SSSDBG_CRIT_FAILURE,
                  "[%s]: ini_config_parse failed [%d][%s]\n",
                  filename, ret, strerror(ret));

            /* Now get specific errors if there are any */
            lret = ini_config_get_errors(ini_config, &errors);
            if (lret != 0) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to get specific parse error [%d][%s]\n", lret,
                      strerror(lret));
                goto done;
            }

            for (int a = 0; errors[a]; a++) {
                 DEBUG(SSSDBG_CRIT_FAILURE, "%s\n", errors[a]);
            }
            ini_config_free_errors(errors);

            goto done;
        }
    }

    for (i = 0; i < GPO_MAP_NUM_OPTS; i++) {
        /* The NO_SID val is used as special SID value for the case when
         * no SIDs are found in the rule, but we need to store some
         * value (SID) with the key (rule name) so that it is clear
         * that the rule is defined on the server. */
        struct gpo_map_option_entry entry = gpo_map_option_entries[i];

        allow_key = entry.allow_key;
        if (allow_key != NULL) {
            DEBUG(SSSDBG_TRACE_ALL, "allow_key = %s\n", allow_key);
            ret = ad_gpo_extract_policy_setting(tmp_ctx,
                                                ini_config,
                                                allow_key,
                                                &allow_value);
            if (ret != EOK && ret != ENOENT) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "ad_gpo_extract_policy_setting failed for %s [%d][%s]\n",
                      allow_key, ret, sss_strerror(ret));
                goto done;
            } else if (ret != ENOENT) {
                const char *value = allow_value ? allow_value : empty_val;
                ret = sysdb_gpo_store_gpo_result_setting(domain,
                                                         allow_key,
                                                         value);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "sysdb_gpo_store_gpo_result_setting failed for key:"
                          "'%s' value:'%s' [%d][%s]\n", allow_key, allow_value,
                          ret, sss_strerror(ret));
                    goto done;
                }
            }
        }

        deny_key = entry.deny_key;
        if (deny_key != NULL) {
            DEBUG(SSSDBG_TRACE_ALL, "deny_key = %s\n", deny_key);
            ret = ad_gpo_extract_policy_setting(tmp_ctx,
                                                ini_config,
                                                deny_key,
                                                &deny_value);
            if (ret != EOK && ret != ENOENT) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "ad_gpo_extract_policy_setting failed for %s [%d][%s]\n",
                      deny_key, ret, sss_strerror(ret));
                goto done;
            } else if (ret != ENOENT) {
                const char *value = deny_value ? deny_value : empty_val;
                ret = sysdb_gpo_store_gpo_result_setting(domain,
                                                         deny_key,
                                                         value);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "sysdb_gpo_store_gpo_result_setting failed for key:"
                          "'%s' value:'%s' [%d][%s]\n", deny_key, deny_value,
                          ret, sss_strerror(ret));
                    goto done;
                }
            }
        }
    }

    ret = EOK;

 done:

    if (ret != EOK) {
      DEBUG(SSSDBG_CRIT_FAILURE, "Error encountered: %d.\n", ret);
    }
    ini_config_file_destroy(file_ctx);
    ini_config_destroy(ini_config);
    talloc_free(tmp_ctx);
    return ret;
}

/*
 * This cse-specific function (GP_EXT_GUID_SECURITY) performs the access
 * check for determining whether logon access is granted or denied for
 * the {user,domain} tuple specified in the inputs. This function returns EOK
 * to indicate that access is granted. Any other return value indicates that
 * access is denied.
 *
 * The access control algorithm first determines whether the "principal_sids"
 * (i.e. user_sid or group_sids) appear in allowed_sids and denied_sids.
 *
 * For access to be granted, both the "allowed_sids_condition" *and* the
 * "denied_sids_condition" must be met (in all other cases, access is denied).
 * 1) The "allowed_sids_condition" is satisfied if any of the principal_sids
 *    appears in allowed_sids OR if the allowed_sids list is empty
 * 2) The "denied_sids_condition" is satisfied if none of the principal_sids
 *    appear in denied_sids
 *
 * Note that a deployment that is unaware of GPO-based access-control policy
 * settings is unaffected by them (b/c absence of allowed_sids grants access).
 *
 * Note that if a principal_sid appears in both allowed_sids and denied_sids,
 * the "allowed_sids_condition" is met, but the "denied_sids_condition" is not.
 * In other words, Deny takes precedence over Allow.
 */
static errno_t
ad_gpo_access_check(TALLOC_CTX *mem_ctx,
                    enum gpo_access_control_mode gpo_mode,
                    enum gpo_map_type gpo_map_type,
                    const char *user,
                    bool gpo_implicit_deny,
                    struct sss_domain_info *domain,
                    struct sss_idmap_ctx *idmap_ctx,
                    char **allowed_sids,
                    int allowed_size,
                    char **denied_sids,
                    int denied_size)
{
    const char *user_sid;
    const char **group_sids;
    int group_size = 0;
    bool access_granted = false;
    bool access_denied = false;
    int ret;
    int j;

    DEBUG(SSSDBG_TRACE_FUNC, "RESULTANT POLICY:\n");
    DEBUG(SSSDBG_TRACE_FUNC, "gpo_map_type: %s\n",
          gpo_map_type_string(gpo_map_type));
    DEBUG(SSSDBG_TRACE_FUNC, "allowed_size = %d\n", allowed_size);
    for (j= 0; j < allowed_size; j++) {
        DEBUG(SSSDBG_TRACE_FUNC, "allowed_sids[%d] = %s\n", j, allowed_sids[j]);
    }

    DEBUG(SSSDBG_TRACE_FUNC, "denied_size = %d\n", denied_size);
    for (j= 0; j < denied_size; j++) {
        DEBUG(SSSDBG_TRACE_FUNC, " denied_sids[%d] = %s\n", j, denied_sids[j]);
    }

    ret = ad_gpo_get_sids(mem_ctx, user, domain, idmap_ctx, &user_sid,
                          &group_sids, &group_size);
    if (ret != EOK) {
        ret = ERR_NO_SIDS;
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to retrieve SIDs: [%d](%s)\n", ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "CURRENT USER:\n");
    DEBUG(SSSDBG_TRACE_FUNC, "       user_sid = %s\n", user_sid);

    for (j= 0; j < group_size; j++) {
        DEBUG(SSSDBG_TRACE_FUNC, "  group_sids[%d] = %s\n", j,
              group_sids[j]);
    }

    if (allowed_size == 0 && !gpo_implicit_deny) {
        access_granted = true;
    }  else {
        access_granted = check_rights(allowed_sids, allowed_size, user_sid,
                                      group_sids, group_size);
    }

    DEBUG(SSSDBG_TRACE_FUNC, "POLICY DECISION:\n");

    DEBUG(SSSDBG_TRACE_FUNC, " access_granted = %d\n", access_granted);

    access_denied = check_rights(denied_sids, denied_size, user_sid,
                                 group_sids, group_size);
    DEBUG(SSSDBG_TRACE_FUNC, "  access_denied = %d\n", access_denied);

    if (access_granted && !access_denied) {
        return EOK;
    } else {
        switch (gpo_mode) {
        case GPO_ACCESS_CONTROL_ENFORCING:
            return ERR_ACCESS_DENIED;
        case GPO_ACCESS_CONTROL_PERMISSIVE:
            DEBUG(SSSDBG_TRACE_FUNC, "access denied: permissive mode\n");
            sss_log_ext(SSS_LOG_WARNING, LOG_AUTHPRIV, "Warning: user would " \
                        "have been denied GPO-based logon access if the " \
                        "ad_gpo_access_control option were set to enforcing " \
                        "mode.");
            return EOK;
        default:
            return EINVAL;
        }
    }

 done:

    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error encountered: %d.\n", ret);
    }

    return ret;
}

/*
 * This function retrieves the raw policy_setting_value for the input key from
 * the GPO_Result object in the sysdb cache. It then parses the raw value and
 * uses the results to populate the output parameters with the sids_list and
 * the size of the sids_list.
 */
errno_t
parse_policy_setting_value(TALLOC_CTX *mem_ctx,
                           struct sss_domain_info *domain,
                           const char *key,
                           char ***_sids_list,
                           int *_sids_list_size)
{
    int ret;
    int i;
    const char *value;
    int sids_list_size;
    char **sids_list = NULL;

    ret = sysdb_gpo_get_gpo_result_setting(mem_ctx, domain, key, &value);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No previous GPO result\n");
        value = NULL;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot retrieve settings from sysdb for key: '%s' [%d][%s].\n",
              key, ret, sss_strerror(ret));
        goto done;
    }

    if (value == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "No value for key [%s] found in gpo result\n", key);
        sids_list_size = 0;
    } else {
        ret = split_on_separator(mem_ctx, value, ',', true, true,
                                 &sids_list, &sids_list_size);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot parse list of sids %s: %d\n", value, ret);
            ret = EINVAL;
            goto done;
        }

        for (i = 0; i < sids_list_size; i++) {
            /* remove the asterisk prefix found on sids */
            sids_list[i]++;
        }
    }

    *_sids_list = talloc_steal(mem_ctx, sids_list);
    *_sids_list_size = sids_list_size;

    ret = EOK;

 done:
    return ret;
}

/*
 * This cse-specific function (GP_EXT_GUID_SECURITY) performs HBAC policy
 * processing and determines whether logon access is granted or denied for
 * the {user,domain} tuple specified in the inputs. This function returns EOK
 * to indicate that access is granted. Any other return value indicates that
 * access is denied.
 *
 * Internally, this function retrieves the allow_value and deny_value for the
 * input gpo_map_type from the GPO Result object in the sysdb cache, parses
 * the values into allow_sids and deny_sids, and executes the access control
 * algorithm which compares the allow_sids and deny_sids against the user_sid
 * and group_sids for the input user.
 */
static errno_t
ad_gpo_perform_hbac_processing(TALLOC_CTX *mem_ctx,
                               enum gpo_access_control_mode gpo_mode,
                               enum gpo_map_type gpo_map_type,
                               const char *user,
                               bool gpo_implicit_deny,
                               struct sss_domain_info *user_domain,
                               struct sss_domain_info *host_domain,
                               struct sss_idmap_ctx *idmap_ctx)
{
    int ret;
    const char *allow_key = NULL;
    char **allow_sids;
    int allow_size ;
    const char *deny_key = NULL;
    char **deny_sids;
    int deny_size;

    allow_key = gpo_map_option_entries[gpo_map_type].allow_key;
    DEBUG(SSSDBG_TRACE_ALL, "allow_key: %s\n", allow_key);
    deny_key = gpo_map_option_entries[gpo_map_type].deny_key;
    DEBUG(SSSDBG_TRACE_ALL, "deny_key: %s\n", deny_key);

    ret = parse_policy_setting_value(mem_ctx, host_domain, allow_key,
                                     &allow_sids, &allow_size);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "parse_policy_setting_value failed for key %s: [%d](%s)\n",
              allow_key, ret, sss_strerror(ret));
        ret = EINVAL;
        goto done;
    }

    ret = parse_policy_setting_value(mem_ctx, host_domain, deny_key,
                                     &deny_sids, &deny_size);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "parse_policy_setting_value failed for key %s: [%d](%s)\n",
              deny_key, ret, sss_strerror(ret));
        ret = EINVAL;
        goto done;
    }

    /* perform access check with the final resultant allow_sids and deny_sids */
    ret = ad_gpo_access_check(mem_ctx, gpo_mode, gpo_map_type, user,
                              gpo_implicit_deny, user_domain, idmap_ctx,
                              allow_sids, allow_size, deny_sids, deny_size);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "GPO access check failed: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto done;
    }

 done:
    return ret;
}

/* == ad_gpo_access_send/recv implementation ================================*/

struct ad_gpo_access_state {
    struct tevent_context *ev;
    struct ldb_context *ldb_ctx;
    struct ad_access_ctx *access_ctx;
    enum gpo_access_control_mode gpo_mode;
    bool gpo_implicit_deny;
    enum gpo_map_type gpo_map_type;
    struct sdap_id_conn_ctx *conn;
    struct sdap_id_op *sdap_op;
    char *server_hostname;
    struct sdap_options *opts;
    int timeout;
    struct sss_domain_info *user_domain;
    struct sss_domain_info *host_domain;
    const char *host_sam_account_name;
    char *host_fqdn;
    const char *user;
    int gpo_timeout_option;
    const char *ad_hostname;
    const char *host_sid;
    const char *target_dn;
    struct gp_gpo **dacl_filtered_gpos;
    int num_dacl_filtered_gpos;
    struct gp_gpo **cse_filtered_gpos;
    int num_cse_filtered_gpos;
    int cse_gpo_index;
    const char *ad_domain;
};

static void ad_gpo_connect_done(struct tevent_req *subreq);
static void ad_gpo_target_dn_retrieval_done(struct tevent_req *subreq);
static void ad_gpo_process_som_done(struct tevent_req *subreq);
static void ad_gpo_process_gpo_done(struct tevent_req *subreq);

static errno_t ad_gpo_cse_step(struct tevent_req *req);
static void ad_gpo_cse_done(struct tevent_req *subreq);

struct tevent_req *
ad_gpo_access_send(TALLOC_CTX *mem_ctx,
                   struct tevent_context *ev,
                   struct sss_domain_info *domain,
                   struct ad_access_ctx *ctx,
                   const char *user,
                   const char *service)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ad_gpo_access_state *state;
    errno_t ret;
    int hret;
    hash_key_t key;
    hash_value_t val;
    enum gpo_map_type gpo_map_type;

    req = tevent_req_create(mem_ctx, &state, struct ad_gpo_access_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    /* determine service's option_type (e.g. interactive, network, etc) */
    key.type = HASH_KEY_STRING;
    key.str = talloc_strdup(state, service);

    hret = hash_lookup(ctx->gpo_map_options_table, &key, &val);
    if (hret != HASH_SUCCESS && hret != HASH_ERROR_KEY_NOT_FOUND) {
        DEBUG(SSSDBG_OP_FAILURE, "Error checking hash table: [%s]\n",
              hash_error_string(hret));
        ret = EINVAL;
        goto immediately;
    }

    /* if service isn't mapped, map it to value of ad_gpo_default_right option */
    if (hret == HASH_ERROR_KEY_NOT_FOUND) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Configuration hint: PAM service '%s' is not mapped to any Group"
              " Policy rule. If you plan to use this PAM service it is "
              "recommended to use the ad_gpo_map_* family of options to map "
              "this PAM service to a Group Policy rule. PAM services not "
              "present in any map will fall back to value set in "
              "ad_gpo_default_right, which is currently set to %s (see manual "
              "pages 'man sssd-ad' for more details).\n", service,
              gpo_map_type_string(ctx->gpo_default_right));
        gpo_map_type = ctx->gpo_default_right;
    } else {
        gpo_map_type = (enum gpo_map_type) val.i;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "service %s maps to %s\n", service,
          gpo_map_type_string(gpo_map_type));

    if (gpo_map_type == GPO_MAP_PERMIT) {
        ret = EOK;
        goto immediately;
    }

    if (gpo_map_type == GPO_MAP_DENY) {
        switch (ctx->gpo_access_control_mode) {
        case GPO_ACCESS_CONTROL_ENFORCING:
            ret = ERR_ACCESS_DENIED;
            goto immediately;
        case GPO_ACCESS_CONTROL_PERMISSIVE:
            DEBUG(SSSDBG_TRACE_FUNC, "access denied: permissive mode\n");
            sss_log_ext(SSS_LOG_WARNING, LOG_AUTHPRIV, "Warning: user would " \
                        "have been denied GPO-based logon access if the " \
                        "ad_gpo_access_control option were set to enforcing " \
                        "mode.");
            ret = EOK;
            goto immediately;
        default:
            ret = EINVAL;
            goto immediately;
        }
    }

    /* GPO Operations all happen against the enrolled domain,
     * not the user's domain (which may be a trusted realm)
     */
    state->user_domain = domain;
    state->host_domain = get_domains_head(domain);
    state->ad_domain = dp_opt_get_string(ctx->ad_id_ctx->ad_options->basic,
                                         AD_DOMAIN);

    state->gpo_map_type = gpo_map_type;
    state->dacl_filtered_gpos = NULL;
    state->num_dacl_filtered_gpos = 0;
    state->cse_filtered_gpos = NULL;
    state->num_cse_filtered_gpos = 0;
    state->cse_gpo_index = 0;
    state->ev = ev;
    state->user = user;
    state->ldb_ctx = sysdb_ctx_get_ldb(state->host_domain->sysdb);
    state->gpo_mode = ctx->gpo_access_control_mode;
    state->gpo_timeout_option = ctx->gpo_cache_timeout;
    state->ad_hostname = dp_opt_get_string(ctx->ad_options, AD_HOSTNAME);
    state->gpo_implicit_deny = dp_opt_get_bool(ctx->ad_options,
                                               AD_GPO_IMPLICIT_DENY);
    state->access_ctx = ctx;
    state->opts = ctx->sdap_access_ctx->id_ctx->opts;
    state->timeout = dp_opt_get_int(state->opts->basic, SDAP_SEARCH_TIMEOUT);
    state->conn = ad_get_dom_ldap_conn(ctx->ad_id_ctx, state->host_domain);
    state->sdap_op = sdap_id_op_create(state, state->conn->conn_cache);
    if (state->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed.\n");
        ret = ENOMEM;
        goto immediately;
    }


    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sdap_id_op_connect_send failed: [%d](%s)\n",
               ret, sss_strerror(ret));
        goto immediately;
    }
    tevent_req_set_callback(subreq, ad_gpo_connect_done, req);

    return req;

immediately:

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }

    tevent_req_post(req, ev);
    return req;
}

static errno_t
process_offline_gpos(TALLOC_CTX *mem_ctx,
                     const char *user,
                     bool gpo_implicit_deny,
                     enum gpo_access_control_mode gpo_mode,
                     struct sss_domain_info *user_domain,
                     struct sss_domain_info *host_domain,
                     struct sss_idmap_ctx *idmap_ctx,
                     enum gpo_map_type gpo_map_type)

{
    errno_t ret;

    ret = ad_gpo_perform_hbac_processing(mem_ctx,
                                         gpo_mode,
                                         gpo_map_type,
                                         user,
                                         gpo_implicit_deny,
                                         user_domain,
                                         host_domain,
                                         idmap_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "HBAC processing failed: [%d](%s}\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* we have successfully processed all offline gpos */
    ret = EOK;

 done:
    return ret;
}

static void
ad_gpo_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_access_state *state;
    int dp_error;
    errno_t ret;
    char *server_uri;
    LDAPURLDesc *lud;
    struct sdap_domain *sdom;
    struct sdap_search_base **search_bases;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_access_state);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        if (dp_error != DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to connect to AD server: [%d](%s)\n",
                  ret, sss_strerror(ret));
            goto done;
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, "Preparing for offline operation.\n");
            ret = process_offline_gpos(state,
                                       state->user,
                                       state->gpo_implicit_deny,
                                       state->gpo_mode,
                                       state->user_domain,
                                       state->host_domain,
                                       state->opts->idmap_ctx->map,
                                       state->gpo_map_type);

            if (ret == EOK) {
                DEBUG(SSSDBG_TRACE_FUNC, "process_offline_gpos succeeded\n");
                tevent_req_done(req);
                goto done;
            } else {
                DEBUG(SSSDBG_OP_FAILURE,
                      "process_offline_gpos failed [%d](%s)\n",
                      ret, sss_strerror(ret));
                goto done;
            }
        }
    }

    /* extract server_hostname from server_uri */
    server_uri = state->conn->service->uri;
    ret = ldap_url_parse(server_uri, &lud);
    if (ret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to parse ldap URI (%s)!\n", server_uri);
        ret = EINVAL;
        goto done;
    }

    if (lud->lud_host == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "The LDAP URI (%s) did not contain a host name\n", server_uri);
        ldap_free_urldesc(lud);
        ret = EINVAL;
        goto done;
    }

    state->server_hostname = talloc_strdup(state, lud->lud_host);
    ldap_free_urldesc(lud);
    if (!state->server_hostname) {
        ret = ENOMEM;
        goto done;
    }
    DEBUG(SSSDBG_TRACE_ALL, "server_hostname from uri: %s\n",
          state->server_hostname);

    /* SDAP_SASL_AUTHID contains the name used for kinit and SASL bind which
     * in the AD case is the NetBIOS name. */
    state->host_sam_account_name = dp_opt_get_string(state->opts->basic,
                                                     SDAP_SASL_AUTHID);
    if (state->host_sam_account_name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "sam_account_name is %s\n",
                             state->host_sam_account_name);

    state->host_fqdn = sss_create_internal_fqname(state, state->host_sam_account_name,
                                                  state->host_domain->name);
    if (state->host_fqdn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to create fully-qualified host name.\n");
        ret = ENOMEM;
        goto done;
    }

    /* AD handle computers the same as users */
    sdom = sdap_domain_get(state->access_ctx->ad_id_ctx->sdap_id_ctx->opts,
                           state->host_domain);
    if (sdom == NULL) {
        ret = EIO;
        goto done;
    }

    ret = common_parse_search_base(state,
                                   sdom->naming_context == NULL ? sdom->basedn
                                                                : sdom->naming_context,
                                   state->ldb_ctx, "AD_HOSTS", NULL, &search_bases);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to create dedicated search base for host lookups, "
              "trying with user search base.");
    }

    subreq = groups_by_user_send(state, state->ev,
                                 state->access_ctx->ad_id_ctx->sdap_id_ctx,
                                 sdom, state->conn,
                                 search_bases,
                                 state->host_fqdn,
                                 BE_FILTER_NAME,
                                 NULL,
                                 true,
                                 true);
    tevent_req_set_callback(subreq, ad_gpo_target_dn_retrieval_done, req);

    ret = EOK;

 done:

    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
}

static void
ad_gpo_target_dn_retrieval_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_access_state *state;
    int ret;
    int dp_error;
    int sdap_ret;
    const char *target_dn = NULL;
    uint32_t uac;
    static const char *host_attrs[] = { SYSDB_ORIG_DN, SYSDB_AD_USER_ACCOUNT_CONTROL, SYSDB_SID_STR, NULL };
    struct ldb_result *res = NULL;
    const char *tmp = NULL;
    char *endptr;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_access_state);
    ret = groups_by_user_recv(subreq, &dp_error, &sdap_ret);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (sdap_ret == EAGAIN && dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_TRACE_FUNC, "Preparing for offline operation.\n");
            ret = process_offline_gpos(state,
                                       state->user,
                                       state->gpo_implicit_deny,
                                       state->gpo_mode,
                                       state->user_domain,
                                       state->host_domain,
                                       state->opts->idmap_ctx->map,
                                       state->gpo_map_type);

            if (ret == EOK) {
                DEBUG(SSSDBG_TRACE_FUNC, "process_offline_gpos succeeded\n");
                tevent_req_done(req);
                goto done;
            } else {
                DEBUG(SSSDBG_OP_FAILURE,
                      "process_offline_gpos failed [%d](%s)\n",
                      ret, sss_strerror(ret));
                goto done;
            }
        }

        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get policy target's DN: [%d](%s)\n",
               ret, sss_strerror(ret));
        ret = ENOENT;
        goto done;
    }

    ret = sysdb_get_user_attr(state, state->host_domain,
                              state->host_fqdn,
                              host_attrs, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to read host attributes.\n");
        goto done;
    }
    if (res->count != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Unexpected number [%d] of results searching "
                                 "for [%s], expected 1.\n", res->count,
                                 state->host_sam_account_name);
        ret = EINVAL;
        goto done;
    }

    target_dn = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_ORIG_DN, NULL);
    if (target_dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_msg_find_attr_as_string failed: [%d](%s)\n",
               ret, sss_strerror(ret));
        goto done;
    }
    state->target_dn = talloc_steal(state, target_dn);
    if (state->target_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tmp = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_AD_USER_ACCOUNT_CONTROL,
                                      NULL);
    if (tmp == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ldb_msg_find_attr_as_string failed: [%d](%s)\n",
               ret, sss_strerror(ret));
        goto done;
    }

    uac = strtouint32(tmp, &endptr, 10);
    if (errno != 0) {
        ret =  errno;
        DEBUG(SSSDBG_OP_FAILURE, "Failed to convert UAC [%s] into uint32_t.\n",
                                 tmp);
        goto done;
    }
    if (*endptr != '\0') {
        ret = EINVAL;
        DEBUG(SSSDBG_OP_FAILURE, "UAC [%s] is not a pure numerical value.\n",
                                 tmp);
        goto done;
    }

    /* we only support computer policy targets, not users */
    if (!(uac & UAC_WORKSTATION_TRUST_ACCOUNT ||
          uac & UAC_SERVER_TRUST_ACCOUNT)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Invalid userAccountControl (%x) value for machine account.\n",
              uac);
        ret = EINVAL;
        goto done;
    }

    state->host_sid = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SID_STR,
                                                  NULL);
    talloc_steal(state, state->host_sid);

    subreq = ad_gpo_process_som_send(state,
                                     state->ev,
                                     state->conn,
                                     state->ldb_ctx,
                                     state->sdap_op,
                                     state->opts,
                                     state->access_ctx->ad_options,
                                     state->timeout,
                                     state->target_dn,
                                     state->ad_domain);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ad_gpo_process_som_done, req);

    ret = EOK;

 done:

    if (ret != EOK) {
        tevent_req_error(req, ret);
    }

}

static void
ad_gpo_process_som_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_access_state *state;
    int ret;
    struct gp_som **som_list;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_access_state);
    ret = ad_gpo_process_som_recv(subreq, state, &som_list);
    talloc_zfree(subreq);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get som list: [%d](%s)\n",
               ret, sss_strerror(ret));
        ret = ENOENT;
        goto done;
    }

    subreq = ad_gpo_process_gpo_send(state,
                                     state->ev,
                                     state->sdap_op,
                                     state->opts,
                                     state->server_hostname,
                                     state->host_domain,
                                     state->access_ctx,
                                     state->timeout,
                                     som_list);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ad_gpo_process_gpo_done, req);

    ret = EOK;

 done:

    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
}

/*
 * This function retrieves a list of candidate_gpos and potentially reduces it
 * to a list of dacl_filtered_gpos, based on each GPO's DACL.
 *
 * This function then takes the list of dacl_filtered_gpos and potentially
 * reduces it to a list of cse_filtered_gpos, based on whether each GPO's list
 * of cse_guids includes the "SecuritySettings" CSE GUID (used for HBAC).
 *
 * Ultimately, this function then sends each cse_filtered_gpo to the gpo_child,
 * which retrieves the GPT.INI and policy files (as needed). Once all files
 * have been downloaded, the ad_gpo_cse_done function performs HBAC processing.
 */
static void
ad_gpo_process_gpo_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_access_state *state;
    int ret;
    int dp_error;
    struct gp_gpo **candidate_gpos = NULL;
    int num_candidate_gpos = 0;
    int i = 0;
    const char **cse_filtered_gpo_guids;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_access_state);
    ret = ad_gpo_process_gpo_recv(subreq, state, &candidate_gpos,
                                  &num_candidate_gpos);

    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);

    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get GPO list from server %s: [%d](%s)\n",
              state->ad_hostname ? state->ad_hostname : "NULL", ret, sss_strerror(ret));
        goto done;
    } else if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "No GPOs found that apply to this system.\n");
        /*
         * Delete the result object list, since there are no
         * GPOs to include in it.
         */
        ret = sysdb_gpo_delete_gpo_result_object(state, state->host_domain);
        if (ret != EOK) {
            switch (ret) {
            case ENOENT:
                DEBUG(SSSDBG_TRACE_FUNC, "No GPO Result available in cache\n");
                break;
            default:
                DEBUG(SSSDBG_FATAL_FAILURE,
                      "Could not delete GPO Result from cache: [%s]\n",
                      sss_strerror(ret));
                goto done;
            }
        }

        if (state->gpo_implicit_deny == true) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "No applicable GPOs have been found and ad_gpo_implicit_deny"
                  " is set to 'true'. The user will be denied access.\n");
            ret = ERR_ACCESS_DENIED;
        } else {
            ret = EOK;
        }

        goto done;
    }

    ret = ad_gpo_filter_gpos_by_dacl(state, state->user, state->host_fqdn,
                                     state->user_domain,
                                     state->host_domain,
                                     state->opts->idmap_ctx->map,
                                     candidate_gpos, num_candidate_gpos,
                                     &state->dacl_filtered_gpos,
                                     &state->num_dacl_filtered_gpos);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to filter GPO list by DACL: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (state->dacl_filtered_gpos[0] == NULL) {
        /* since no applicable gpos were found, there is nothing to enforce */
        DEBUG(SSSDBG_TRACE_FUNC,
              "no applicable gpos found after dacl filtering\n");

        /*
         * Delete the result object list, since there are no
         * GPOs to include in it.
         */
        ret = sysdb_gpo_delete_gpo_result_object(state, state->host_domain);
        if (ret != EOK) {
            switch (ret) {
            case ENOENT:
                DEBUG(SSSDBG_TRACE_FUNC, "No GPO Result available in cache\n");
                break;
            default:
                DEBUG(SSSDBG_FATAL_FAILURE,
                      "Could not delete GPO Result from cache: [%s]\n",
                      sss_strerror(ret));
                goto done;
            }
        }

        if (state->gpo_implicit_deny == true) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "No applicable GPOs have been found and ad_gpo_implicit_deny"
                  " is set to 'true'. The user will be denied access.\n");
            ret = ERR_ACCESS_DENIED;
        } else {
            ret = EOK;
        }

        goto done;
    }

    for (i = 0; i < state->num_dacl_filtered_gpos; i++) {
        DEBUG(SSSDBG_TRACE_FUNC, "dacl_filtered_gpos[%d]->gpo_guid is %s\n", i,
              state->dacl_filtered_gpos[i]->gpo_guid);
    }

    ret = ad_gpo_filter_gpos_by_cse_guid(state,
                                         GP_EXT_GUID_SECURITY,
                                         state->dacl_filtered_gpos,
                                         state->num_dacl_filtered_gpos,
                                         &state->cse_filtered_gpos,
                                         &state->num_cse_filtered_gpos);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to filter GPO list by CSE_GUID: [%d](%s)\n",
               ret, sss_strerror(ret));
        goto done;
    }

    if (state->cse_filtered_gpos[0] == NULL) {
        /* no gpos contain "SecuritySettings" cse_guid, nothing to enforce */
        DEBUG(SSSDBG_TRACE_FUNC,
              "no applicable gpos found after cse_guid filtering\n");

        if (state->gpo_implicit_deny == true) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "No applicable GPOs have been found and ad_gpo_implicit_deny"
                  " is set to 'true'. The user will be denied access.\n");
            ret = ERR_ACCESS_DENIED;
        } else {
            ret = EOK;
        }

        goto done;
    }

    /* we create and populate an array of applicable gpo-guids */
    cse_filtered_gpo_guids =
        talloc_array(state, const char *, state->num_cse_filtered_gpos);
    if (cse_filtered_gpo_guids == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < state->num_cse_filtered_gpos; i++) {
        DEBUG(SSSDBG_TRACE_FUNC, "cse_filtered_gpos[%d]->gpo_guid is %s\n", i,
                                  state->cse_filtered_gpos[i]->gpo_guid);
        cse_filtered_gpo_guids[i] = talloc_steal(cse_filtered_gpo_guids,
                                                 state->cse_filtered_gpos[i]->gpo_guid);
        if (cse_filtered_gpo_guids[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "num_cse_filtered_gpos: %d\n",
          state->num_cse_filtered_gpos);

    /*
     * before we start processing each gpo, we delete the GPO Result object
     * from the sysdb cache so that any previous policy settings are cleared;
     * subsequent functions will add the GPO Result object (and populate it
     * with resultant policy settings) for this policy application
     */
    ret = sysdb_gpo_delete_gpo_result_object(state, state->host_domain);
    if (ret != EOK) {
        switch (ret) {
        case ENOENT:
            DEBUG(SSSDBG_TRACE_FUNC, "No GPO Result available in cache\n");
            break;
        default:
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Could not delete GPO Result from cache: [%s]\n",
                  sss_strerror(ret));
            goto done;
        }
    }

    ret = ad_gpo_cse_step(req);

 done:

    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }
}

static errno_t
ad_gpo_cse_step(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct ad_gpo_access_state *state;
    int i = 0;
    struct ldb_result *res;
    errno_t ret;
    bool send_to_child = true;
    int cached_gpt_version = 0;
    time_t policy_file_timeout = 0;

    state = tevent_req_data(req, struct ad_gpo_access_state);

    struct gp_gpo *cse_filtered_gpo =
        state->cse_filtered_gpos[state->cse_gpo_index];

    /* cse_filtered_gpo is NULL after all GPO policy files have been downloaded */
    if (cse_filtered_gpo == NULL) return EOK;

    DEBUG(SSSDBG_TRACE_FUNC, "cse filtered_gpos[%d]->gpo_guid is %s\n",
          state->cse_gpo_index, cse_filtered_gpo->gpo_guid);
    for (i = 0; i < cse_filtered_gpo->num_gpo_cse_guids; i++) {
        DEBUG(SSSDBG_TRACE_ALL,
              "cse_filtered_gpos[%d]->gpo_cse_guids[%d]->gpo_guid is %s\n",
              state->cse_gpo_index, i, cse_filtered_gpo->gpo_cse_guids[i]);
    }

    DEBUG(SSSDBG_TRACE_FUNC, "smb_server: %s\n", cse_filtered_gpo->smb_server);
    DEBUG(SSSDBG_TRACE_FUNC, "smb_share: %s\n", cse_filtered_gpo->smb_share);
    DEBUG(SSSDBG_TRACE_FUNC, "smb_path: %s\n", cse_filtered_gpo->smb_path);
    DEBUG(SSSDBG_TRACE_FUNC, "gpo_guid: %s\n", cse_filtered_gpo->gpo_guid);

    cse_filtered_gpo->policy_filename =
        talloc_asprintf(state,
                        GPO_CACHE_PATH"%s%s",
                        cse_filtered_gpo->smb_path,
                        GP_EXT_GUID_SECURITY_SUFFIX);
    if (cse_filtered_gpo->policy_filename == NULL) {
        return ENOMEM;
    }

    /* retrieve gpo cache entry; set cached_gpt_version to -1 if unavailable */
    DEBUG(SSSDBG_TRACE_FUNC, "retrieving GPO from cache [%s]\n",
          cse_filtered_gpo->gpo_guid);
    ret = sysdb_gpo_get_gpo_by_guid(state,
                                    state->host_domain,
                                    cse_filtered_gpo->gpo_guid,
                                    &res);
    if (ret == EOK) {
        /*
         * Note: if the timeout is valid, then we can later avoid downloading
         * the GPT.INI file, as well as any policy files (i.e. we don't need
         * to interact with the gpo_child at all). However, even if the timeout
         * is not valid, while we will have to interact with the gpo child to
         * download the GPT.INI file, we may still be able to avoid downloading
         * the policy files (if the cached_gpt_version is the same as the
         * GPT.INI version). In other words, the timeout is *not* an expiration
         * for the entire cache entry; the cached_gpt_version never expires.
         */

        cached_gpt_version = ldb_msg_find_attr_as_int(res->msgs[0],
                                                      SYSDB_GPO_VERSION_ATTR,
                                                      0);

        policy_file_timeout = ldb_msg_find_attr_as_uint64
            (res->msgs[0], SYSDB_GPO_TIMEOUT_ATTR, 0);

        if (policy_file_timeout >= time(NULL)) {
            send_to_child = false;
        }
    } else if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "ENOENT\n");
        cached_gpt_version = -1;
    } else {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not read GPO from cache: [%s]\n",
              sss_strerror(ret));
        return ret;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "send_to_child: %d\n", send_to_child);
    DEBUG(SSSDBG_TRACE_FUNC, "cached_gpt_version: %d\n", cached_gpt_version);

    cse_filtered_gpo->send_to_child = send_to_child;

    subreq = ad_gpo_process_cse_send(state,
                                     state->ev,
                                     send_to_child,
                                     state->host_domain,
                                     cse_filtered_gpo->gpo_guid,
                                     cse_filtered_gpo->smb_server,
                                     cse_filtered_gpo->smb_share,
                                     cse_filtered_gpo->smb_path,
                                     GP_EXT_GUID_SECURITY_SUFFIX,
                                     cached_gpt_version,
                                     state->gpo_timeout_option);

    tevent_req_set_callback(subreq, ad_gpo_cse_done, req);
    return EAGAIN;
}

/*
 * This cse-specific function (GP_EXT_GUID_SECURITY) increments the
 * cse_gpo_index until the policy settings for all applicable GPOs have been
 * stored as part of the GPO Result object in the sysdb cache. Once all
 * GPOs have been processed, this functions performs HBAC processing by
 * comparing the resultant policy setting values in the GPO Result object
 * with the user_sid/group_sids of interest.
 */
static void
ad_gpo_cse_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_access_state *state;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_access_state);

    struct gp_gpo *cse_filtered_gpo =
        state->cse_filtered_gpos[state->cse_gpo_index];

    const char *gpo_guid = cse_filtered_gpo->gpo_guid;

    DEBUG(SSSDBG_TRACE_FUNC, "gpo_guid: %s\n", gpo_guid);

    ret = ad_gpo_process_cse_recv(subreq);

    talloc_zfree(subreq);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to retrieve policy data: [%d](%s}\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /*
     * now that the policy file for this gpo have been downloaded to the
     * GPO CACHE, we store all of the supported keys present in the file
     * (as part of the GPO Result object in the sysdb cache).
     */
    ret = ad_gpo_store_policy_settings(state->host_domain,
                                       cse_filtered_gpo->policy_filename);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ad_gpo_store_policy_settings failed: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto done;
    }

    state->cse_gpo_index++;
    ret = ad_gpo_cse_step(req);

    if (ret == EOK) {
        /* ret is EOK only after all GPO policy files have been downloaded */
        ret = ad_gpo_perform_hbac_processing(state,
                                             state->gpo_mode,
                                             state->gpo_map_type,
                                             state->user,
                                             state->gpo_implicit_deny,
                                             state->user_domain,
                                             state->host_domain,
                                             state->opts->idmap_ctx->map);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "HBAC processing failed: [%d](%s}\n",
                  ret, sss_strerror(ret));
            goto done;
        }

    }

 done:

    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }
}

errno_t
ad_gpo_access_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* == ad_gpo_process_som_send/recv helpers ================================= */

/*
 * This function returns the parent of an LDAP DN
 */
static errno_t
ad_gpo_parent_dn(TALLOC_CTX *mem_ctx,
                 struct ldb_context *ldb_ctx,
                 const char *dn,
                 const char **_parent_dn)
{
    struct ldb_dn *ldb_dn;
    struct ldb_dn *parent_ldb_dn;
    const char *p;
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ldb_dn = ldb_dn_new(tmp_ctx, ldb_ctx, dn);
    parent_ldb_dn = ldb_dn_get_parent(tmp_ctx, ldb_dn);
    p = ldb_dn_get_linearized(parent_ldb_dn);

    *_parent_dn = talloc_steal(mem_ctx, p);
    ret = EOK;

 done:
    talloc_free(tmp_ctx);
    return ret;
}

/*
 * This function populates the _som_list output parameter by parsing the input
 * DN into a list of gp_som objects. This function essentially repeatedly
 * appends the input DN's parent to the SOM List (if the parent starts with
 * "OU=" or "DC="), until the first "DC=" component is reached.
 * Example: if input DN is "CN=MyComputer,CN=Computers,OU=Sales,DC=FOO,DC=COM",
 * then SOM List has 2 SOM entries: {[OU=Sales,DC=FOO,DC=COM], [DC=FOO, DC=COM]}
 */

static errno_t
ad_gpo_populate_som_list(TALLOC_CTX *mem_ctx,
                         struct ldb_context *ldb_ctx,
                         const char *target_dn,
                         int *_num_soms,
                         struct gp_som ***_som_list)
{
    TALLOC_CTX *tmp_ctx = NULL;
    int ret;
    int rdn_count = 0;
    int som_idx = 0;
    struct gp_som **som_list;
    const char *parent_dn = NULL;
    const char *tmp_dn = NULL;
    struct ldb_dn *ldb_target_dn;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ldb_target_dn = ldb_dn_new(tmp_ctx, ldb_ctx, target_dn);
    if (ldb_target_dn == NULL) {
        ret = EINVAL;
        goto done;
    }

    rdn_count = ldb_dn_get_comp_num(ldb_target_dn);
    if (rdn_count == -1) {
        ret = EINVAL;
        goto done;
    }

    if (rdn_count == 0) {
        *_som_list = NULL;
        ret = EOK;
        goto done;
    }

    /* assume the worst-case, in which every parent is a SOM */
    /* include space for Site SOM and NULL: rdn_count + 1 + 1 */
    som_list = talloc_array(tmp_ctx, struct gp_som *, rdn_count + 1 + 1);
    if (som_list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* first, populate the OU and Domain SOMs */
    tmp_dn = target_dn;
    while ((ad_gpo_parent_dn(tmp_ctx, ldb_ctx, tmp_dn, &parent_dn)) == EOK) {

        if ((strncasecmp(parent_dn, "OU=", strlen("OU=")) == 0) ||
            (strncasecmp(parent_dn, "DC=", strlen("DC=")) == 0)) {

            som_list[som_idx] = talloc_zero(som_list, struct gp_som);
            if (som_list[som_idx] == NULL) {
                ret = ENOMEM;
                goto done;
            }
            som_list[som_idx]->som_dn = talloc_steal(som_list[som_idx],
                                                     parent_dn);
            if (som_list[som_idx]->som_dn == NULL) {
                ret = ENOMEM;
                goto done;
            }
            som_idx++;
        }

        if (strncasecmp(parent_dn, "DC=", strlen("DC=")) == 0) {
            break;
        }
        tmp_dn = parent_dn;
    }

    som_list[som_idx] = NULL;

    *_num_soms = som_idx;
    *_som_list = talloc_steal(mem_ctx, som_list);

    ret = EOK;

 done:
    talloc_free(tmp_ctx);
    return ret;
}

/*
 * This function populates the _gplink_list output parameter by parsing the
 * input raw_gplink_value into an array of gp_gplink objects, each consisting of
 * a GPO DN and bool enforced field.
 *
 * The raw_gplink_value is single string consisting of multiple gplink strings.
 * The raw_gplink_value is in the following format:
 *  "[GPO_DN_1;GPLinkOptions_1]...[GPO_DN_n;GPLinkOptions_n]"
 *
 * Each gplink string consists of a GPO DN and a GPLinkOptions field (which
 * indicates whether its associated GPO DN is ignored, unenforced, or enforced).
 * If a GPO DN is flagged as ignored, it is discarded and will not be added to
 * the _gplink_list. If the allow_enforced_only input is true, AND a GPO DN is
 * flagged as unenforced, it will also be discarded.
 *
 * Example: if raw_gplink_value="[OU=Sales,DC=FOO,DC=COM;0][DC=FOO,DC=COM;2]"
 *   and allow_enforced_only=FALSE, then the output would consist of following:
 *    _gplink_list[0]: {GPO DN: "OU=Sales,DC=FOO,DC=COM", enforced: FALSE}
 *    _gplink_list[1]: {GPO DN: "DC=FOO,DC=COM",          enforced: TRUE}
 */
static errno_t
ad_gpo_populate_gplink_list(TALLOC_CTX *mem_ctx,
                            const char *som_dn,
                            char *raw_gplink_value,
                            struct gp_gplink ***_gplink_list,
                            bool allow_enforced_only)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *ptr;
    char *first;
    char *last;
    char *dn;
    char *gplink_options;
    const char delim = ']';
    struct gp_gplink **gplink_list;
    int i;
    int ret;
    uint32_t gplink_number;
    int gplink_count = 0;
    int num_enabled = 0;

    if (raw_gplink_value == NULL ||
        *raw_gplink_value == '\0' ||
        _gplink_list == NULL) {
        return EINVAL;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "som_dn: %s\n", som_dn);
    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ptr = raw_gplink_value;

    while ((ptr = strchr(ptr, delim))) {
        ptr++;
        gplink_count++;
    }

    if (gplink_count == 0) {
        ret = EOK;
        goto done;
    }

    gplink_list = talloc_array(tmp_ctx, struct gp_gplink *, gplink_count + 1);
    if (gplink_list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    num_enabled = 0;
    ptr = raw_gplink_value;
    for (i = 0; i < gplink_count; i++) {
        first = ptr + 1;
        last = strchr(first, delim);
        if (last == NULL) {
            ret = EINVAL;
            goto done;
        }
        *last = '\0';
        last++;
        dn = first;
        if ( strncasecmp(dn, "LDAP://", 7)== 0 ) {
            dn = dn + 7;
        }
        gplink_options = strchr(first, ';');
        if (gplink_options == NULL) {
            ret = EINVAL;
            goto done;
        }
        *gplink_options = '\0';
        gplink_options++;

        gplink_number = strtouint32(gplink_options, NULL, 10);
        if (errno != 0) {
            ret = errno;
            DEBUG(SSSDBG_OP_FAILURE,
                  "strtouint32 failed: [%d](%s)\n", ret, sss_strerror(ret));
            goto done;
        }

        DEBUG(SSSDBG_TRACE_ALL,
              "gplink_list[%d]: [%s; %d]\n", num_enabled, dn, gplink_number);

        if ((gplink_number == 1) || (gplink_number ==3)) {
            /* ignore flag is set */
            DEBUG(SSSDBG_TRACE_ALL, "ignored gpo skipped\n");
            ptr = last;
            continue;
        }

        if (allow_enforced_only && (gplink_number == 0)) {
            /* unenforced flag is set; only enforced gpos allowed */
            DEBUG(SSSDBG_TRACE_ALL, "unenforced gpo skipped\n");
            ptr = last;
            continue;
        }

        gplink_list[num_enabled] = talloc_zero(gplink_list, struct gp_gplink);
        if (gplink_list[num_enabled] == NULL) {
            ret = ENOMEM;
            goto done;
        }
        gplink_list[num_enabled]->gpo_dn =
            talloc_strdup(gplink_list[num_enabled], dn);

        if (gplink_list[num_enabled]->gpo_dn == NULL) {
            ret = ENOMEM;
            goto done;
        }

        if (gplink_number == 0) {
            gplink_list[num_enabled]->enforced = 0;
            num_enabled++;
        } else if (gplink_number == 2) {
            gplink_list[num_enabled]->enforced = 1;
            num_enabled++;
        } else {
            ret = EINVAL;
            goto done;
        }

        ptr = last;
    }
    gplink_list[num_enabled] = NULL;

    *_gplink_list = talloc_steal(mem_ctx, gplink_list);
    ret = EOK;

 done:
    talloc_free(tmp_ctx);
    return ret;
}

/* == ad_gpo_process_som_send/recv implementation ========================== */

struct ad_gpo_process_som_state {
    struct tevent_context *ev;
    struct sdap_id_op *sdap_op;
    struct sdap_options *opts;
    struct dp_option *ad_options;
    int timeout;
    bool allow_enforced_only;
    char *site_name;
    char *site_dn;
    struct gp_som **som_list;
    int som_index;
    int num_soms;
};

static void ad_gpo_site_name_retrieval_done(struct tevent_req *subreq);
static void ad_gpo_site_dn_retrieval_done(struct tevent_req *subreq);
static errno_t ad_gpo_get_som_attrs_step(struct tevent_req *req);
static void ad_gpo_get_som_attrs_done(struct tevent_req *subreq);

/*
 * This function uses the input target_dn and input domain_name to populate
 * a list of gp_som objects. Each object in this list represents a SOM
 * associated with the target (such as OU, Domain, and Site).
 *
 * The inputs are used to determine the DNs of each SOM associated with the
 * target. In turn, the SOM object DNs are used to retrieve certain LDAP
 * attributes of each SOM object, that are parsed into an array of gp_gplink
 * objects, essentially representing the GPOs that have been linked to each
 * SOM object. Note that it is perfectly valid for there to be *no* GPOs
 * linked to a SOM object.
 */
struct tevent_req *
ad_gpo_process_som_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct sdap_id_conn_ctx *conn,
                        struct ldb_context *ldb_ctx,
                        struct sdap_id_op *sdap_op,
                        struct sdap_options *opts,
                        struct dp_option *ad_options,
                        int timeout,
                        const char *target_dn,
                        const char *domain_name)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ad_gpo_process_som_state *state;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ad_gpo_process_som_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->sdap_op = sdap_op;
    state->opts = opts;
    state->ad_options = ad_options;
    state->timeout = timeout;
    state->som_index = 0;
    state->allow_enforced_only = 0;

    ret = ad_gpo_populate_som_list(state, ldb_ctx, target_dn,
                                   &state->num_soms, &state->som_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to retrieve SOM List : [%d](%s)\n",
              ret, sss_strerror(ret));
        ret = ENOENT;
        goto immediately;
    }

    if (state->som_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "target dn must have at least one parent\n");
        ret = EINVAL;
        goto immediately;
    }

    subreq = ad_domain_info_send(state, state->ev, conn,
                                 state->sdap_op, domain_name);

    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ad_domain_info_send failed.\n");
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ad_gpo_site_name_retrieval_done, req);

    ret = EOK;

 immediately:

    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void
ad_gpo_site_name_retrieval_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_process_som_state *state;
    int ret;
    char *site = NULL;
    char *site_override = NULL;
    const char *attrs[] = {AD_AT_CONFIG_NC, NULL};

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_process_som_state);

    /* gpo code only cares about the site name */
    ret = ad_domain_info_recv(subreq, state, NULL, NULL, &site, NULL);
    talloc_zfree(subreq);

    if (ret != EOK || site == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Could not autodiscover AD site. This is not fatal if "
              "ad_site option was set.\n");
    }

    site_override = dp_opt_get_string(state->ad_options, AD_SITE);
    if (site_override != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Overriding autodiscovered AD site value '%s' with '%s' from "
              "configuration.\n", site ? site : "none", site_override);
    }

    if (site == NULL && site_override == NULL) {
        sss_log(SSS_LOG_WARNING,
                "Could not autodiscover AD site value using DNS and ad_site "
                "option was not set in configuration. GPO will not work. "
                "To work around this issue you can use ad_site option in SSSD "
                "configuration.");
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not autodiscover AD site value using DNS and ad_site "
              "option was not set in configuration. GPO will not work. "
              "To work around this issue you can use ad_site option in SSSD "
              "configuration.\n");
        tevent_req_error(req, ENOENT);
        return;
    }

    state->site_name = talloc_asprintf(state, "cn=%s",
                                       site_override ? site_override
                                                     : site);
    if (state->site_name == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Using AD site '%s'.\n", state->site_name);

    /*
     * note: the configNC attribute is being retrieved here from the rootDSE
     * entry. In future, since we already make an LDAP query for the rootDSE
     * entry when LDAP connection is made, this attribute should really be
     * retrieved at that point (see https://fedorahosted.org/sssd/ticket/2276)
     */
    subreq = sdap_get_generic_send(state, state->ev, state->opts,
                                   sdap_id_op_handle(state->sdap_op),
                                   "", LDAP_SCOPE_BASE,
                                   "(objectclass=*)", attrs, NULL, 0,
                                   state->timeout,
                                   false);

    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send failed.\n");
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, ad_gpo_site_dn_retrieval_done, req);
}

static void
ad_gpo_site_dn_retrieval_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_process_som_state *state;
    int ret;
    int dp_error;
    int i = 0;
    size_t reply_count;
    struct sysdb_attrs **reply;
    const char *configNC;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_process_som_state);

    ret = sdap_get_generic_recv(subreq, state,
                                &reply_count, &reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);

        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get configNC: [%d](%s)\n", ret, sss_strerror(ret));
        ret = ENOENT;
        goto done;
    }

    /* make sure there is only one non-NULL reply returned */

    if (reply_count < 1) {
        DEBUG(SSSDBG_OP_FAILURE, "No configNC retrieved\n");
        ret = ENOENT;
        goto done;
    } else if (reply_count > 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Multiple replies for configNC\n");
        ret = ERR_INTERNAL;
        goto done;
    } else if (reply == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "reply_count is 1, but reply is NULL\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    /* reply[0] holds requested attributes of single reply */
    ret = sysdb_attrs_get_string(reply[0], AD_AT_CONFIG_NC, &configNC);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_attrs_get_string failed: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto done;
    }
    state->site_dn =
        talloc_asprintf(state, "%s,cn=Sites,%s", state->site_name, configNC);
    if (state->site_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* note that space was allocated for site_dn when allocating som_list */
    state->som_list[state->num_soms] =
        talloc_zero(state->som_list, struct gp_som);
    if (state->som_list[state->num_soms] == NULL) {
        ret = ENOMEM;
        goto done;
    }

    state->som_list[state->num_soms]->som_dn =
        talloc_steal(state->som_list[state->num_soms], state->site_dn);

    if (state->som_list[state->num_soms]->som_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    state->num_soms++;
    state->som_list[state->num_soms] = NULL;

    i = 0;
    while (state->som_list[i]) {
        DEBUG(SSSDBG_TRACE_FUNC, "som_list[%d]->som_dn is %s\n", i,
              state->som_list[i]->som_dn);
        i++;
    }

    ret = ad_gpo_get_som_attrs_step(req);

 done:

    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

}
static errno_t
ad_gpo_get_som_attrs_step(struct tevent_req *req)
{
    const char *attrs[] = {AD_AT_GPLINK, AD_AT_GPOPTIONS, NULL};
    struct tevent_req *subreq;
    struct ad_gpo_process_som_state *state;

    state = tevent_req_data(req, struct ad_gpo_process_som_state);

    struct gp_som *gp_som = state->som_list[state->som_index];

    /* gp_som is NULL only after all SOMs have been processed */
    if (gp_som == NULL) return EOK;

    const char *som_dn = gp_som->som_dn;
    subreq = sdap_get_generic_send(state, state->ev,  state->opts,
                                   sdap_id_op_handle(state->sdap_op),
                                   som_dn, LDAP_SCOPE_BASE,
                                   "(objectclass=*)", attrs, NULL, 0,
                                   state->timeout,
                                   false);

    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send failed.\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ad_gpo_get_som_attrs_done, req);
    return EAGAIN;
}

static void
ad_gpo_get_som_attrs_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_process_som_state *state;
    int ret;
    int dp_error;
    size_t num_results;
    struct sysdb_attrs **results;
    struct ldb_message_element *el = NULL;
    uint8_t *raw_gplink_value;
    uint8_t *raw_gpoptions_value;
    uint32_t allow_enforced_only = 0;
    struct gp_som *gp_som;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_process_som_state);
    ret = sdap_get_generic_recv(subreq, state,
                                &num_results, &results);
    talloc_zfree(subreq);

    if (ret != EOK) {
        ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);

        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get SOM attributes: [%d](%s)\n",
              ret, sss_strerror(ret));
        ret = ENOENT;
        goto done;
    }
    if ((num_results < 1) || (results == NULL)) {
        DEBUG(SSSDBG_FUNC_DATA, "no attrs found for SOM; try next SOM.\n");
        state->som_index++;
        ret = ad_gpo_get_som_attrs_step(req);
        goto done;
    } else if (num_results > 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Received multiple replies\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    /* Get the gplink value, if available */
    ret = sysdb_attrs_get_el(results[0], AD_AT_GPLINK, &el);

    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_attrs_get_el() failed: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if ((ret == ENOENT) || (el->num_values == 0)) {
        DEBUG(SSSDBG_FUNC_DATA, "gpLink attr not found or has no values\n");
        state->som_index++;
        ret = ad_gpo_get_som_attrs_step(req);
        goto done;
    }

    raw_gplink_value = el[0].values[0].data;

    ret = sysdb_attrs_get_el(results[0], AD_AT_GPOPTIONS, &el);

    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_el() failed\n");
        goto done;
    }

    if ((ret == ENOENT) || (el->num_values == 0)) {
        DEBUG(SSSDBG_TRACE_ALL,
              "gpoptions attr not found or has no value; defaults to 0\n");
        allow_enforced_only = 0;
    }  else {
        raw_gpoptions_value = el[0].values[0].data;
        allow_enforced_only = strtouint32((char *)raw_gpoptions_value, NULL, 10);
        if (errno != 0) {
            ret = errno;
            DEBUG(SSSDBG_OP_FAILURE,
                  "strtouint32 failed: [%d](%s)\n", ret, sss_strerror(ret));
            goto done;
        }
    }

    gp_som = state->som_list[state->som_index];
    ret = ad_gpo_populate_gplink_list(gp_som,
                                      gp_som->som_dn,
                                      (char *)raw_gplink_value,
                                      &gp_som->gplink_list,
                                      state->allow_enforced_only);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ad_gpo_populate_gplink_list() failed\n");
        goto done;
    }

    if (allow_enforced_only) {
        state->allow_enforced_only = 1;
    }

    state->som_index++;
    ret = ad_gpo_get_som_attrs_step(req);

 done:

    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }
}

int
ad_gpo_process_som_recv(struct tevent_req *req,
                        TALLOC_CTX *mem_ctx,
                        struct gp_som ***som_list)
{

    struct ad_gpo_process_som_state *state =
        tevent_req_data(req, struct ad_gpo_process_som_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *som_list = talloc_steal(mem_ctx, state->som_list);
    return EOK;
}

/* == ad_gpo_process_gpo_send/recv helpers ================================= */

/*
 * This function examines the gp_gplink objects in each gp_som object specified
 * in the input som_list, and populates the _candidate_gpos output parameter's
 * gpo_dn fields with prioritized list of GPO DNs. Prioritization ensures that:
 * - GPOs linked to an OU will be applied after GPOs linked to a Domain,
 *   which will be applied after GPOs linked to a Site.
 * - multiple GPOs linked to a single SOM are applied in their link order
 *   (i.e. 1st GPO linked to SOM is applied before 2nd GPO linked to SOM, etc).
 * - enforced GPOs are applied after unenforced GPOs.
 *
 * As such, the _candidate_gpos output's dn fields looks like (in link order):
 * [unenforced {Site, Domain, OU}; enforced {OU, Domain, Site}]
 *
 * Note that in the case of conflicting policy settings, GPOs appearing later
 * in the list will trump GPOs appearing earlier in the list. Therefore the
 * enforced GPOs are applied in revers order after the unenforced GPOs to
 * make sure the enforced setting form the highest level will be applied.
 *
 * GPO processing details can be found e.g. at
 * https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581922(v%3Dws.11)
 */
static errno_t
ad_gpo_populate_candidate_gpos(TALLOC_CTX *mem_ctx,
                               struct gp_som **som_list,
                               struct gp_gpo ***_candidate_gpos,
                               int *_num_candidate_gpos)
{

    TALLOC_CTX *tmp_ctx = NULL;
    struct gp_som *gp_som = NULL;
    struct gp_gplink *gp_gplink = NULL;
    struct gp_gpo **candidate_gpos = NULL;
    int num_candidate_gpos = 0;
    const char **enforced_gpo_dns = NULL;
    const char **unenforced_gpo_dns = NULL;
    int gpo_dn_idx = 0;
    int num_enforced = 0;
    int enforced_idx = 0;
    int num_unenforced = 0;
    int unenforced_idx = 0;
    int i = 0;
    int j = 0;
    int ret;
    size_t som_count = 0;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    while (som_list[i]) {
        gp_som = som_list[i];
        j = 0;
        while (gp_som && gp_som->gplink_list && gp_som->gplink_list[j]) {
            gp_gplink = gp_som->gplink_list[j];
            if (gp_gplink == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "unexpected null gp_gplink\n");
                ret = EINVAL;
                goto done;
            }
            if (gp_gplink->enforced) {
                num_enforced++;
            } else {
                num_unenforced++;
            }
            j++;
        }
        i++;
    }
    som_count = i;

    num_candidate_gpos = num_enforced + num_unenforced;

    if (num_candidate_gpos == 0) {
        *_candidate_gpos = NULL;
        *_num_candidate_gpos = 0;
        ret = EOK;
        goto done;
    }

    enforced_gpo_dns = talloc_array(tmp_ctx, const char *, num_enforced + 1);
    if (enforced_gpo_dns == NULL) {
        ret = ENOMEM;
        goto done;
    }

    unenforced_gpo_dns = talloc_array(tmp_ctx, const char *, num_unenforced + 1);
    if (unenforced_gpo_dns == NULL) {
        ret = ENOMEM;
        goto done;
    }

    i = som_count -1 ;
    while (i >= 0) {
        gp_som = som_list[i];

        /* For unenforced_gpo_dns the most specific GPOs with the highest
         * priority should be the last. We start with the top-level SOM and go
         * down to the most specific one and add the unenforced following the
         * gplink_list where the GPO with the highest priority comes last. */
        j = 0;
        while (gp_som && gp_som->gplink_list && gp_som->gplink_list[j]) {
                gp_gplink = gp_som->gplink_list[j];

                if (!gp_gplink->enforced) {
                    unenforced_gpo_dns[unenforced_idx] =
                        talloc_steal(unenforced_gpo_dns, gp_gplink->gpo_dn);

                    if (unenforced_gpo_dns[unenforced_idx] == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }
                    unenforced_idx++;
                }
                j++;
        }
        i--;
    }

    i = 0;
    while (som_list[i]) {
        gp_som = som_list[i];

        /* For enforced GPOs we start processing with the most specific SOM to
         * make sur enforced GPOs from higher levels override to lower level
         * ones. According to the 'Group Policy Inheritance' tab in the
         * Windows 'Goup Policy Management' utility in the same SOM the link
         * order is still observed and an enforced GPO with a lower link order
         * value still overrides an enforced GPO with a higher link order. */
        j = 0;
        while (gp_som && gp_som->gplink_list && gp_som->gplink_list[j]) {
            gp_gplink = gp_som->gplink_list[j];
            if (gp_gplink == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "unexpected null gp_gplink\n");
                ret = EINVAL;
                goto done;
            }

            if (gp_gplink->enforced) {
                enforced_gpo_dns[enforced_idx] =
                    talloc_steal(enforced_gpo_dns, gp_gplink->gpo_dn);
                if (enforced_gpo_dns[enforced_idx] == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
                enforced_idx++;
            }
            j++;
        }
        i++;
    }
    enforced_gpo_dns[num_enforced] = NULL;
    unenforced_gpo_dns[num_unenforced] = NULL;

    candidate_gpos = talloc_array(tmp_ctx,
                                  struct gp_gpo *,
                                  num_candidate_gpos + 1);

    if (candidate_gpos == NULL) {
        ret = ENOMEM;
        goto done;
    }

    gpo_dn_idx = 0;
    for (i = 0; i < num_unenforced; i++) {
        candidate_gpos[gpo_dn_idx] = talloc_zero(candidate_gpos, struct gp_gpo);
        if (candidate_gpos[gpo_dn_idx] == NULL) {
            ret = ENOMEM;
            goto done;
        }
        candidate_gpos[gpo_dn_idx]->gpo_dn =
            talloc_steal(candidate_gpos[gpo_dn_idx], unenforced_gpo_dns[i]);

        if (candidate_gpos[gpo_dn_idx]->gpo_dn == NULL) {
            ret = ENOMEM;
            goto done;
        }
        DEBUG(SSSDBG_TRACE_FUNC,
              "candidate_gpos[%d]->gpo_dn: %s\n",
              gpo_dn_idx, candidate_gpos[gpo_dn_idx]->gpo_dn);
        gpo_dn_idx++;
    }

    for (i = 0; i < num_enforced; i++) {

        candidate_gpos[gpo_dn_idx] = talloc_zero(candidate_gpos, struct gp_gpo);
        if (candidate_gpos[gpo_dn_idx] == NULL) {
            ret = ENOMEM;
            goto done;
        }

        candidate_gpos[gpo_dn_idx]->gpo_dn =
            talloc_steal(candidate_gpos[gpo_dn_idx], enforced_gpo_dns[i]);
        if (candidate_gpos[gpo_dn_idx]->gpo_dn == NULL) {
            ret = ENOMEM;
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC,
              "candidate_gpos[%d]->gpo_dn: %s\n",
              gpo_dn_idx, candidate_gpos[gpo_dn_idx]->gpo_dn);
        gpo_dn_idx++;
    }

    candidate_gpos[gpo_dn_idx] = NULL;

    *_candidate_gpos = talloc_steal(mem_ctx, candidate_gpos);
    *_num_candidate_gpos = num_candidate_gpos;

    ret = EOK;

 done:
    talloc_free(tmp_ctx);
    return ret;
}

/*
 * This function parses the input_path into its components, replaces each
 * back slash ('\') with a forward slash ('/'), and populates the output params.
 *
 * The smb_server output is constructed by concatenating the following elements:
 * - SMB_STANDARD_URI ("smb://")
 * - server_hostname (which replaces domain_name in input path)
 * The smb_share and smb_path outputs are extracted from the input_path.
 *
 * Example: if input_path = "\\foo.com\SysVol\foo.com\..." and
 * server_hostname = "adserver.foo.com", then
 *   _smb_server = "smb://adserver.foo.com"
 *   _smb_share = "SysVol"
 *   _smb_path = "/foo.com/..."
 *
 * Note that the input_path must have at least four forward slash separators.
 * For example, input_path = "\\foo.com\SysVol" is not a valid input_path,
 * because it has only three forward slash separators.
 */
static errno_t
ad_gpo_extract_smb_components(TALLOC_CTX *mem_ctx,
                              char *server_hostname,
                              char *input_path,
                              const char **_smb_server,
                              const char **_smb_share,
                              const char **_smb_path)
{
    char *ptr;
    const char delim = '\\';
    int ret;
    int num_seps = 0;
    char *smb_path = NULL;
    char *smb_share = NULL;

    DEBUG(SSSDBG_TRACE_ALL, "input_path: %s\n", input_path);

    if (input_path == NULL ||
        *input_path == '\0' ||
        _smb_server == NULL ||
        _smb_share == NULL ||
        _smb_path == NULL) {
        ret = EINVAL;
        goto done;
    }

    ptr = input_path;
    while ((ptr = strchr(ptr, delim))) {
        num_seps++;
        if (num_seps == 3) {
            /* replace the slash before the share name with null string */

            *ptr = '\0';
            ptr++;
            smb_share = ptr;
            continue;
        } else if (num_seps == 4) {
            /* replace the slash after the share name with null string */
            *ptr = '\0';
            ptr++;
            smb_path = ptr;
            continue;
        }
        *ptr = '/';
        ptr++;
    }

    if (num_seps == 0) {
        ret = EINVAL;
        goto done;
    }

    if (smb_path == NULL)  {
        ret = EINVAL;
        goto done;
    }

    *_smb_server = talloc_asprintf(mem_ctx, "%s%s",
                                   SMB_STANDARD_URI,
                                   server_hostname);
    if (*_smb_server == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *_smb_share = talloc_asprintf(mem_ctx, "/%s", smb_share);
    if (*_smb_share == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *_smb_path = talloc_asprintf(mem_ctx, "/%s", smb_path);
    if (*_smb_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

 done:
    return ret;
}

/*
 * This function populates the _cse_guid_list output parameter by parsing the
 * input raw_machine_ext_names_value into an array of cse_guid strings.
 *
 * The raw_machine_ext_names_value is a single string in the following format:
 * "[{cse_guid_1}{tool_guid1}]...[{cse_guid_n}{tool_guid_n}]"
 */
static errno_t
ad_gpo_parse_machine_ext_names(TALLOC_CTX *mem_ctx,
                               char *raw_machine_ext_names_value,
                               const char ***_gpo_cse_guids,
                               int *_num_gpo_cse_guids)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *ptr;
    char *first;
    char *last;
    char *cse_guid;
    char *tool_guid;
    const char delim = ']';
    const char **gpo_cse_guids;
    int i;
    int ret;
    int num_gpo_cse_guids = 0;

    if (raw_machine_ext_names_value == NULL ||
        *raw_machine_ext_names_value == '\0' ||
        _gpo_cse_guids == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ptr = raw_machine_ext_names_value;
    while ((ptr = strchr(ptr, delim))) {
        ptr++;
        num_gpo_cse_guids++;
    }

    if (num_gpo_cse_guids == 0) {
        ret = EINVAL;
        goto done;
    }

    gpo_cse_guids = talloc_array(tmp_ctx, const char *, num_gpo_cse_guids + 1);
    if (gpo_cse_guids == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ptr = raw_machine_ext_names_value;
    for (i = 0; i < num_gpo_cse_guids; i++) {
        first = ptr + 1;
        last = strchr(first, delim);
        if (last == NULL) {
            break;
        }
        *last = '\0';
        last++;
        cse_guid = first;
        first ++;
        tool_guid = strchr(first, '{');
        if (tool_guid == NULL) {
            break;
        }
        *tool_guid = '\0';
        gpo_cse_guids[i] = talloc_strdup(gpo_cse_guids, cse_guid);
        ptr = last;
    }
    gpo_cse_guids[i] = NULL;

    DEBUG(SSSDBG_TRACE_ALL, "num_gpo_cse_guids: %d\n", num_gpo_cse_guids);

    for (i = 0; i < num_gpo_cse_guids; i++) {
        DEBUG(SSSDBG_TRACE_ALL,
              "gpo_cse_guids[%d] is %s\n", i, gpo_cse_guids[i]);
    }

    *_gpo_cse_guids = talloc_steal(mem_ctx, gpo_cse_guids);
    *_num_gpo_cse_guids = num_gpo_cse_guids;
    ret = EOK;

 done:
    talloc_free(tmp_ctx);
    return ret;
}

enum ndr_err_code
ad_gpo_ndr_pull_security_descriptor(struct ndr_pull *ndr, int ndr_flags,
                                    struct security_descriptor *r);

/*
 * This function parses the input data blob and assigns the resulting
 * security_descriptor object to the _gpo_sd output parameter.
 */
static errno_t ad_gpo_parse_sd(TALLOC_CTX *mem_ctx,
                               uint8_t *data,
                               size_t length,
                               struct security_descriptor **_gpo_sd)
{

    struct ndr_pull *ndr_pull = NULL;
    struct security_descriptor sd;
    DATA_BLOB blob;
    enum ndr_err_code ndr_err;

    blob.data = data;
    blob.length = length;

    ndr_pull = ndr_pull_init_blob(&blob, mem_ctx);
    if (ndr_pull == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ndr_pull_init_blob() failed.\n");
        return EINVAL;
    }

    ndr_err = ad_gpo_ndr_pull_security_descriptor(ndr_pull,
                                                  NDR_SCALARS|NDR_BUFFERS,
                                                  &sd);

    if (ndr_err != NDR_ERR_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to pull security descriptor\n");
        return EINVAL;
    }

    *_gpo_sd = talloc_memdup(mem_ctx, &sd, sizeof(struct security_descriptor));

    return EOK;
}

/* == ad_gpo_process_gpo_send/recv implementation ========================== */

struct ad_gpo_process_gpo_state {
    struct ad_access_ctx *access_ctx;
    struct tevent_context *ev;
    struct sdap_id_op *sdap_op;
    struct dp_option *ad_options;
    struct sdap_options *opts;
    char *server_hostname;
    struct sss_domain_info *host_domain;
    int timeout;
    struct gp_gpo **candidate_gpos;
    int num_candidate_gpos;
    int gpo_index;
};

static errno_t ad_gpo_get_gpo_attrs_step(struct tevent_req *req);
static void ad_gpo_get_gpo_attrs_done(struct tevent_req *subreq);

/*
 * This function uses the input som_list to populate a prioritized list of
 * gp_gpo objects, prioritized based on SOM type, link order, and whether the
 * GPO is "enforced". This list represents the initial set of candidate GPOs
 * that might be applicable to the target. This list can not be expanded, but
 * it might be reduced based on subsequent filtering steps. The GPO object DNs
 * are used to retrieve certain LDAP attributes of each GPO object, that are
 * parsed into the various fields of the gp_gpo object.
 */
struct tevent_req *
ad_gpo_process_gpo_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct sdap_id_op *sdap_op,
                        struct sdap_options *opts,
                        char *server_hostname,
                        struct sss_domain_info *host_domain,
                        struct ad_access_ctx *access_ctx,
                        int timeout,
                        struct gp_som **som_list)
{
    struct tevent_req *req;
    struct ad_gpo_process_gpo_state *state;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ad_gpo_process_gpo_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->sdap_op = sdap_op;
    state->ad_options = access_ctx->ad_options;
    state->opts = opts;
    state->server_hostname = server_hostname;
    state->host_domain = host_domain;
    state->access_ctx = access_ctx;
    state->timeout = timeout;
    state->gpo_index = 0;
    state->candidate_gpos = NULL;
    state->num_candidate_gpos = 0;

    ret = ad_gpo_populate_candidate_gpos(state,
                                         som_list,
                                         &state->candidate_gpos,
                                         &state->num_candidate_gpos);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to retrieve GPO List: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto immediately;
    }

    if (state->candidate_gpos == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "no gpos found\n");
        ret = ENOENT;
        goto immediately;
    }

    ret = ad_gpo_get_gpo_attrs_step(req);

immediately:

    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static errno_t
ad_gpo_get_gpo_attrs_step(struct tevent_req *req)
{
    const char *attrs[] = AD_GPO_ATTRS;
    struct tevent_req *subreq;
    struct ad_gpo_process_gpo_state *state;

    state = tevent_req_data(req, struct ad_gpo_process_gpo_state);

    struct gp_gpo *gp_gpo = state->candidate_gpos[state->gpo_index];

    /* gp_gpo is NULL only after all GPOs have been processed */
    if (gp_gpo == NULL) return EOK;

    const char *gpo_dn = gp_gpo->gpo_dn;

    subreq = sdap_sd_search_send(state, state->ev,
                                 state->opts, sdap_id_op_handle(state->sdap_op),
                                 gpo_dn, SECINFO_DACL, attrs, state->timeout);

    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_sd_search_send failed.\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ad_gpo_get_gpo_attrs_done, req);
    return EAGAIN;
}

static errno_t
ad_gpo_sd_process_attrs(struct tevent_req *req,
                        char *smb_host,
                        struct sysdb_attrs *result);
void
ad_gpo_get_sd_referral_done(struct tevent_req *subreq);

static struct tevent_req *
ad_gpo_get_sd_referral_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct ad_access_ctx *access_ctx,
                            struct sdap_options *opts,
                            const char *referral,
                            struct sss_domain_info *host_domain,
                            int timeout);
errno_t
ad_gpo_get_sd_referral_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            char **_smb_host,
                            struct sysdb_attrs **_reply);

static void
ad_gpo_get_gpo_attrs_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_process_gpo_state *state;
    int ret;
    int dp_error;
    size_t num_results, refcount;
    struct sysdb_attrs **results;
    char **refs;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_process_gpo_state);

    ret = sdap_sd_search_recv(subreq, state,
                              &num_results, &results,
                              &refcount, &refs);
    talloc_zfree(subreq);

    if (ret != EOK) {
        ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);

        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get GPO attributes: [%d](%s)\n",
              ret, sss_strerror(ret));
        ret = ENOENT;
        goto done;
    }

    if ((num_results < 1) || (results == NULL)) {
        if (refcount == 1) {
            /* If we were redirected to a referral, process it.
             * There must be a single referral result here; if we get
             * more than one (or zero) it's a bug.
             */

            subreq = ad_gpo_get_sd_referral_send(state, state->ev,
                                                 state->access_ctx,
                                                 state->opts,
                                                 refs[0],
                                                 state->host_domain,
                                                 state->timeout);
            if (!subreq) {
                ret = ENOMEM;
                goto done;
            }

            tevent_req_set_callback(subreq, ad_gpo_get_sd_referral_done, req);
            ret = EAGAIN;
            goto done;

        } else {
            const char *gpo_dn = state->candidate_gpos[state->gpo_index]->gpo_dn;

            DEBUG(SSSDBG_OP_FAILURE,
                  "No attrs found for GPO [%s].\n", gpo_dn);
            ret = ENOENT;
            goto done;
        }
    } else if (num_results > 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Received multiple replies\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    ret = ad_gpo_sd_process_attrs(req, state->server_hostname, results[0]);

done:

   if (ret == EOK) {
       tevent_req_done(req);
   } else if (ret != EAGAIN) {
       tevent_req_error(req, ret);
   }
}

void
ad_gpo_get_sd_referral_done(struct tevent_req *subreq)
{
    errno_t ret;
    int dp_error;
    struct sysdb_attrs *reply;
    char *smb_host;

    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ad_gpo_process_gpo_state *state =
            tevent_req_data(req, struct ad_gpo_process_gpo_state);

    ret = ad_gpo_get_sd_referral_recv(subreq, state, &smb_host, &reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        /* Terminate the sdap_id_op */
        ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);

        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get referred GPO attributes: [%d](%s)\n",
              ret, sss_strerror(ret));

        goto done;
    }

    /* Lookup succeeded. Process it */
    ret = ad_gpo_sd_process_attrs(req, smb_host, reply);

done:

   if (ret == EOK) {
       tevent_req_done(req);
   } else if (ret != EAGAIN) {
       tevent_req_error(req, ret);
   }
}

static bool machine_ext_names_is_blank(char *attr_value)
{
    char *ptr;

    if (attr_value == NULL) {
        return true;
    }

    ptr = attr_value;
    for (; *ptr != '\0'; ptr++) {
        if (!isspace(*ptr)) {
            return false;
        }
    }

    return true;
}

static errno_t
ad_gpo_missing_or_unreadable_attr(struct ad_gpo_process_gpo_state *state,
                                  struct tevent_req *req)
{
    bool ignore_unreadable = dp_opt_get_bool(state->ad_options,
                                             AD_GPO_IGNORE_UNREADABLE);

    if (ignore_unreadable) {
        /* If admins decided to skip GPOs with unreadable
         * attributes just log the SID of skipped GPO */
        DEBUG(SSSDBG_TRACE_FUNC,
              "Group Policy Container with DN [%s] has unreadable or missing "
              "attributes -> skipping this GPO "
              "(ad_gpo_ignore_unreadable = True)\n",
              state->candidate_gpos[state->gpo_index]->gpo_dn);
        state->gpo_index++;
        return ad_gpo_get_gpo_attrs_step(req);
    } else {
        /* Inform in logs and syslog that this GPO can
         * not be processed due to unreadable or missing
         * attributes and point to possible server side
         * and client side solutions. */
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Group Policy Container with DN [%s] is unreadable or has "
              "unreadable or missing attributes. In order to fix this "
              "make sure that this AD object has following attributes "
              "readable: nTSecurityDescriptor, cn, gPCFileSysPath, "
              "gPCMachineExtensionNames, gPCFunctionalityVersion, flags. "
              "Alternatively if you do not have access to the server or can "
              "not change permissions on this object, you can use option "
              "ad_gpo_ignore_unreadable = True which will skip this GPO. "
              "See ad_gpo_ignore_unreadable in 'man sssd-ad' for details.\n",
              state->candidate_gpos[state->gpo_index]->gpo_dn);
        sss_log(SSS_LOG_ERR,
                "Group Policy Container with DN [%s] is unreadable or has "
                "unreadable or missing attributes. In order to fix this "
                "make sure that this AD object has following attributes "
                "readable: nTSecurityDescriptor, cn, gPCFileSysPath, "
                "gPCMachineExtensionNames, gPCFunctionalityVersion, flags. "
                "Alternatively if you do not have access to the server or can "
                "not change permissions on this object, you can use option "
                "ad_gpo_ignore_unreadable = True which will skip this GPO. "
                "See ad_gpo_ignore_unreadable in 'man sssd-ad' for details.\n",
                state->candidate_gpos[state->gpo_index]->gpo_dn);
        return EFAULT;
    }
}

static errno_t
ad_gpo_sd_process_attrs(struct tevent_req *req,
                        char *smb_host,
                        struct sysdb_attrs *result)
{
    struct ad_gpo_process_gpo_state *state;
    struct gp_gpo *gp_gpo;
    int ret;
    struct ldb_message_element *el = NULL;
    const char *gpo_guid = NULL;
    const char *raw_file_sys_path = NULL;
    char *file_sys_path = NULL;
    uint8_t *raw_machine_ext_names = NULL;

    state = tevent_req_data(req, struct ad_gpo_process_gpo_state);
    gp_gpo = state->candidate_gpos[state->gpo_index];

    /* retrieve AD_AT_CN */
    ret = sysdb_attrs_get_string(result, AD_AT_CN, &gpo_guid);
    if (ret == ENOENT) {
        ret = ad_gpo_missing_or_unreadable_attr(state, req);
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_attrs_get_string failed: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto done;
    }

    gp_gpo->gpo_guid = talloc_steal(gp_gpo, gpo_guid);
    if (gp_gpo->gpo_guid == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "populating attrs for gpo_guid: %s\n",
          gp_gpo->gpo_guid);

    /* retrieve AD_AT_FILE_SYS_PATH */
    ret = sysdb_attrs_get_string(result,
                                 AD_AT_FILE_SYS_PATH,
                                 &raw_file_sys_path);

    if (ret == ENOENT) {
        ret = ad_gpo_missing_or_unreadable_attr(state, req);
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_attrs_get_string failed: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto done;
    }

    file_sys_path = talloc_strdup(gp_gpo, raw_file_sys_path);

    ret = ad_gpo_extract_smb_components(gp_gpo, smb_host,
                                        file_sys_path, &gp_gpo->smb_server,
                                        &gp_gpo->smb_share, &gp_gpo->smb_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "unable to extract smb components from file_sys_path: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "smb_server: %s\n", gp_gpo->smb_server);
    DEBUG(SSSDBG_TRACE_ALL, "smb_share: %s\n", gp_gpo->smb_share);
    DEBUG(SSSDBG_TRACE_ALL, "smb_path: %s\n", gp_gpo->smb_path);

    /* retrieve AD_AT_FUNC_VERSION */
    ret = sysdb_attrs_get_int32_t(result, AD_AT_FUNC_VERSION,
                                  &gp_gpo->gpo_func_version);
    if (ret == ENOENT) {
        /* If this attribute is missing we can skip the GPO. It will
         * be filtered out according to MS-GPOL:
         * https://msdn.microsoft.com/en-us/library/cc232538.aspx */
        DEBUG(SSSDBG_TRACE_ALL, "GPO with GUID %s is missing attribute "
              AD_AT_FUNC_VERSION " and will be skipped.\n", gp_gpo->gpo_guid);
        state->gpo_index++;
        ret = ad_gpo_get_gpo_attrs_step(req);
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_attrs_get_int32_t failed: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "gpo_func_version: %d\n",
                            gp_gpo->gpo_func_version);

    /* retrieve AD_AT_FLAGS */
    ret = sysdb_attrs_get_int32_t(result, AD_AT_FLAGS,
                                  &gp_gpo->gpo_flags);
    if (ret == ENOENT) {
        ret = ad_gpo_missing_or_unreadable_attr(state, req);
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_attrs_get_int32_t failed: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "gpo_flags: %d\n", gp_gpo->gpo_flags);

    /* retrieve AD_AT_NT_SEC_DESC */
    ret = sysdb_attrs_get_el(result, AD_AT_NT_SEC_DESC, &el);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_el() failed\n");
        goto done;
    }
    if ((ret == ENOENT) || (el->num_values == 0)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "nt_sec_desc attribute not found or has no value\n");
        ret = ad_gpo_missing_or_unreadable_attr(state, req);
        goto done;
    }

    ret = ad_gpo_parse_sd(gp_gpo, el[0].values[0].data, el[0].values[0].length,
                          &gp_gpo->gpo_sd);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ad_gpo_parse_sd() failed\n");
        goto done;
    }

    /* retrieve AD_AT_MACHINE_EXT_NAMES */
    ret = sysdb_attrs_get_el(result, AD_AT_MACHINE_EXT_NAMES, &el);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_el() failed\n");
        goto done;
    }

    if ((ret == ENOENT) || (el->num_values == 0)
            || machine_ext_names_is_blank((char *) el[0].values[0].data)) {
        /*
         * if gpo has no machine_ext_names (which is perfectly valid: it could
         * have only user_ext_names, for example), we continue to next gpo
         */
        DEBUG(SSSDBG_TRACE_ALL,
              "machine_ext_names attribute not found or has no value\n");
        state->gpo_index++;
    } else {
        raw_machine_ext_names = el[0].values[0].data;

        ret = ad_gpo_parse_machine_ext_names(gp_gpo,
                                             (char *)raw_machine_ext_names,
                                             &gp_gpo->gpo_cse_guids,
                                             &gp_gpo->num_gpo_cse_guids);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "ad_gpo_parse_machine_ext_names() failed\n");
            goto done;
        }

        state->gpo_index++;
    }

    ret = ad_gpo_get_gpo_attrs_step(req);

 done:

    return ret;
}

int
ad_gpo_process_gpo_recv(struct tevent_req *req,
                        TALLOC_CTX *mem_ctx,
                        struct gp_gpo ***candidate_gpos,
                        int *num_candidate_gpos)
{
    struct ad_gpo_process_gpo_state *state =
        tevent_req_data(req, struct ad_gpo_process_gpo_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *candidate_gpos = talloc_steal(mem_ctx, state->candidate_gpos);
    *num_candidate_gpos = state->num_candidate_gpos;
    return EOK;
}

/* == ad_gpo_process_cse_send/recv helpers ================================= */
static errno_t
create_cse_send_buffer(TALLOC_CTX *mem_ctx,
                       const char *smb_server,
                       const char *smb_share,
                       const char *smb_path,
                       const char *smb_cse_suffix,
                       int cached_gpt_version,
                       struct io_buffer **io_buf)
{
    struct io_buffer *buf;
    size_t rp;
    int smb_server_length;
    int smb_share_length;
    int smb_path_length;
    int smb_cse_suffix_length;

    smb_server_length = strlen(smb_server);
    smb_share_length = strlen(smb_share);
    smb_path_length = strlen(smb_path);
    smb_cse_suffix_length = strlen(smb_cse_suffix);

    buf = talloc(mem_ctx, struct io_buffer);
    if (buf == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
        return ENOMEM;
    }

    buf->size = 5 * sizeof(uint32_t);
    buf->size += smb_server_length + smb_share_length + smb_path_length +
        smb_cse_suffix_length;

    DEBUG(SSSDBG_TRACE_ALL, "buffer size: %zu\n", buf->size);

    buf->data = talloc_size(buf, buf->size);
    if (buf->data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        talloc_free(buf);
        return ENOMEM;
    }

    rp = 0;
    /* cached_gpt_version */
    SAFEALIGN_SET_UINT32(&buf->data[rp], cached_gpt_version, &rp);

    /* smb_server */
    SAFEALIGN_SET_UINT32(&buf->data[rp], smb_server_length, &rp);
    safealign_memcpy(&buf->data[rp], smb_server, smb_server_length, &rp);

    /* smb_share */
    SAFEALIGN_SET_UINT32(&buf->data[rp], smb_share_length, &rp);
    safealign_memcpy(&buf->data[rp], smb_share, smb_share_length, &rp);

    /* smb_path */
    SAFEALIGN_SET_UINT32(&buf->data[rp], smb_path_length, &rp);
    safealign_memcpy(&buf->data[rp], smb_path, smb_path_length, &rp);

    /* smb_cse_suffix */
    SAFEALIGN_SET_UINT32(&buf->data[rp], smb_cse_suffix_length, &rp);
    safealign_memcpy(&buf->data[rp], smb_cse_suffix, smb_cse_suffix_length, &rp);

    *io_buf = buf;
    return EOK;
}

static errno_t
ad_gpo_parse_gpo_child_response(uint8_t *buf,
                                ssize_t size,
                                uint32_t *_sysvol_gpt_version,
                                uint32_t *_result)
{

    int ret;
    size_t p = 0;
    uint32_t sysvol_gpt_version;
    uint32_t result;

    /* sysvol_gpt_version */
    SAFEALIGN_COPY_UINT32_CHECK(&sysvol_gpt_version, buf + p, size, &p);

    /* operation result code */
    SAFEALIGN_COPY_UINT32_CHECK(&result, buf + p, size, &p);

    *_sysvol_gpt_version = sysvol_gpt_version;
    *_result = result;

    ret = EOK;
    return ret;
}

/* == ad_gpo_process_cse_send/recv implementation ========================== */

struct ad_gpo_process_cse_state {
    struct tevent_context *ev;
    struct sss_domain_info *domain;
    int gpo_timeout_option;
    const char *gpo_guid;
    const char *smb_path;
    const char *smb_cse_suffix;
    pid_t child_pid;
    uint8_t *buf;
    ssize_t len;
    struct child_io_fds *io;
};

static errno_t gpo_fork_child(struct tevent_req *req);
static void gpo_cse_step(struct tevent_req *subreq);
static void gpo_cse_done(struct tevent_req *subreq);

/*
 * This cse-specific function (GP_EXT_GUID_SECURITY) sends the input smb uri
 * components and cached_gpt_version to the gpo child, which, in turn,
 * will download the GPT.INI file and policy files (as needed) and store
 * them in the GPO_CACHE directory. Note that if the send_to_child input is
 * false, this function simply completes the request.
 */
struct tevent_req *
ad_gpo_process_cse_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        bool send_to_child,
                        struct sss_domain_info *domain,
                        const char *gpo_guid,
                        const char *smb_server,
                        const char *smb_share,
                        const char *smb_path,
                        const char *smb_cse_suffix,
                        int cached_gpt_version,
                        int gpo_timeout_option)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ad_gpo_process_cse_state *state;
    struct io_buffer *buf = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ad_gpo_process_cse_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (!send_to_child) {
        /*
         * if we don't need to talk to child (b/c cache timeout is still valid),
         * we simply complete the request
         */
        ret = EOK;
        goto immediately;
    }

    state->ev = ev;
    state->buf = NULL;
    state->len = 0;
    state->domain = domain;
    state->gpo_timeout_option = gpo_timeout_option;
    state->gpo_guid = gpo_guid;
    state->smb_path = smb_path;
    state->smb_cse_suffix = smb_cse_suffix;
    state->io = talloc(state, struct child_io_fds);
    if (state->io == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
        ret = ENOMEM;
        goto immediately;
    }

    state->io->write_to_child_fd = -1;
    state->io->read_from_child_fd = -1;
    talloc_set_destructor((void *) state->io, child_io_destructor);

    /* prepare the data to pass to child */
    ret = create_cse_send_buffer(state, smb_server, smb_share, smb_path,
                                 smb_cse_suffix, cached_gpt_version, &buf);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "create_cse_send_buffer failed.\n");
        goto immediately;
    }

    ret = gpo_fork_child(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "gpo_fork_child failed.\n");
        goto immediately;
    }

    subreq = write_pipe_send(state, ev, buf->data, buf->size,
                             state->io->write_to_child_fd);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }
    tevent_req_set_callback(subreq, gpo_cse_step, req);

    return req;

immediately:

    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void gpo_cse_step(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_process_cse_state *state;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_process_cse_state);

    ret = write_pipe_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    PIPE_FD_CLOSE(state->io->write_to_child_fd);

    subreq = read_pipe_send(state, state->ev, state->io->read_from_child_fd);

    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, gpo_cse_done, req);
}

static void gpo_cse_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_process_cse_state *state;
    uint32_t sysvol_gpt_version = -1;
    uint32_t child_result;
    time_t now;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_process_cse_state);
    int ret;

    ret = read_pipe_recv(subreq, state, &state->buf, &state->len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    PIPE_FD_CLOSE(state->io->read_from_child_fd);

    ret = ad_gpo_parse_gpo_child_response(state->buf, state->len,
                                          &sysvol_gpt_version, &child_result);
    if (ret != EOK) {
        if (ret == EINVAL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ad_gpo_parse_gpo_child_response failed: [%d][%s]. "
                  "Broken GPO data received from AD. Check AD child logs for "
                  "more information.\n",
                  ret, sss_strerror(ret));
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "ad_gpo_parse_gpo_child_response failed: [%d][%s]\n",
                  ret, sss_strerror(ret));
        }

        tevent_req_error(req, ret);
        return;
    } else if (child_result != 0){
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Error in gpo_child: [%d][%s]\n",
              child_result, strerror(child_result));
        tevent_req_error(req, child_result);
        return;
    }

    now = time(NULL);
    DEBUG(SSSDBG_TRACE_FUNC, "sysvol_gpt_version: %d\n", sysvol_gpt_version);
    ret = sysdb_gpo_store_gpo(state->domain, state->gpo_guid, sysvol_gpt_version,
                              state->gpo_timeout_option, now);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to store gpo cache entry: [%d](%s}\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

int ad_gpo_process_cse_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

static errno_t
gpo_fork_child(struct tevent_req *req)
{
    int pipefd_to_child[2] = PIPE_INIT;
    int pipefd_from_child[2] = PIPE_INIT;
    pid_t pid;
    errno_t ret;
    const char **extra_args;
    int c = 0;
    struct ad_gpo_process_cse_state *state;

    state = tevent_req_data(req, struct ad_gpo_process_cse_state);

    extra_args = talloc_array(state, const char *, 2);

    extra_args[c] = talloc_asprintf(extra_args, "--chain-id=%lu",
                                    sss_chain_id_get());
    if (extra_args[c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto fail;
    }
    c++;

    extra_args[c] = NULL;

    ret = pipe(pipefd_from_child);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe (from) failed [%d][%s].\n", errno, strerror(errno));
        goto fail;
    }
    ret = pipe(pipefd_to_child);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe (to) failed [%d][%s].\n", errno, strerror(errno));
        goto fail;
    }

    pid = fork();

    if (pid == 0) { /* child */
        exec_child_ex(state,
                      pipefd_to_child, pipefd_from_child,
                      GPO_CHILD, GPO_CHILD_LOG_FILE, extra_args, false,
                      STDIN_FILENO, AD_GPO_CHILD_OUT_FILENO);

        /* We should never get here */
        DEBUG(SSSDBG_CRIT_FAILURE, "BUG: Could not exec gpo_child:\n");
    } else if (pid > 0) { /* parent */
        state->child_pid = pid;
        state->io->read_from_child_fd = pipefd_from_child[0];
        PIPE_FD_CLOSE(pipefd_from_child[1]);
        state->io->write_to_child_fd = pipefd_to_child[1];
        PIPE_FD_CLOSE(pipefd_to_child[0]);
        sss_fd_nonblocking(state->io->read_from_child_fd);
        sss_fd_nonblocking(state->io->write_to_child_fd);

        ret = child_handler_setup(state->ev, pid, NULL, NULL, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Could not set up child signal handler\n");
            goto fail;
        }
    } else { /* error */
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "fork failed [%d][%s].\n", errno, strerror(errno));
        goto fail;
    }

    return EOK;

fail:
    PIPE_CLOSE(pipefd_from_child);
    PIPE_CLOSE(pipefd_to_child);
    return ret;
}

struct ad_gpo_get_sd_referral_state {
    struct tevent_context *ev;
    struct ad_access_ctx *access_ctx;
    struct sdap_options *opts;
    struct sss_domain_info *host_domain;
    struct sss_domain_info *ref_domain;
    struct sdap_id_conn_ctx *conn;
    struct sdap_id_op *ref_op;
    int timeout;
    char *gpo_dn;
    char *smb_host;


    struct sysdb_attrs *reply;
};

static void
ad_gpo_get_sd_referral_conn_done(struct tevent_req *subreq);

static struct tevent_req *
ad_gpo_get_sd_referral_send(TALLOC_CTX *mem_ctx,
                            struct tevent_context *ev,
                            struct ad_access_ctx *access_ctx,
                            struct sdap_options *opts,
                            const char *referral,
                            struct sss_domain_info *host_domain,
                            int timeout)
{
    errno_t ret;
    struct tevent_req *req;
    struct ad_gpo_get_sd_referral_state *state;
    struct tevent_req *subreq;
    LDAPURLDesc *lud = NULL;

    req = tevent_req_create(mem_ctx, &state,
                            struct ad_gpo_get_sd_referral_state);
    if (!req) return NULL;

    state->ev = ev;
    state->access_ctx = access_ctx;
    state->opts = opts;
    state->host_domain = host_domain;
    state->timeout = timeout;

    /* Parse the URL for the domain */
    ret = ldap_url_parse(referral, &lud);
    if (ret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to parse referral URI (%s)!\n", referral);
        ret = EINVAL;
        goto done;
    }

    state->gpo_dn = talloc_strdup(state, lud->lud_dn);
    if (!state->gpo_dn) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not copy referral DN (%s)!\n", lud->lud_dn);
        ldap_free_urldesc(lud);
        ret = ENOMEM;
        goto done;
    }

    /* Active Directory returns the domain name as the hostname
     * in these referrals, so we can use that to look up the
     * necessary connection.
     */
    state->ref_domain = find_domain_by_name(state->host_domain,
                                            lud->lud_host, true);
    if (!state->ref_domain) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not find domain matching [%s]\n",
              lud->lud_host);
        ldap_free_urldesc(lud);
        ret = EIO;
        goto done;
    }

    ldap_free_urldesc(lud);
    lud = NULL;

    state->conn = ad_get_dom_ldap_conn(state->access_ctx->ad_id_ctx,
                                       state->ref_domain);
    if (!state->conn) {
        DEBUG(SSSDBG_OP_FAILURE,
              "No connection for %s\n", state->ref_domain->name);
        ret = EINVAL;
        goto done;
    }

    /* Get the hostname we're going to connect to.
     * We'll need this later for performing the samba
     * connection.
     */
    ret = ldap_url_parse(state->conn->service->uri, &lud);
    if (ret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to parse service URI (%s)!\n", referral);
        ret = EINVAL;
        goto done;
    }

    state->smb_host = talloc_strdup(state, lud->lud_host);
    ldap_free_urldesc(lud);
    if (!state->smb_host) {
        ret = ENOMEM;
        goto done;
    }

    /* Start an ID operation for the referral */
    state->ref_op = sdap_id_op_create(state, state->conn->conn_cache);
    if (!state->ref_op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed.\n");
        ret = ENOMEM;
        goto done;
    }

    /* Establish the sdap_id_op connection */
    subreq = sdap_id_op_connect_send(state->ref_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_connect_send failed: %d(%s).\n",
                                  ret, sss_strerror(ret));
        goto done;
    }
    tevent_req_set_callback(subreq, ad_gpo_get_sd_referral_conn_done, req);

done:

    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static void
ad_gpo_get_sd_referral_search_done(struct tevent_req *subreq);

static void
ad_gpo_get_sd_referral_conn_done(struct tevent_req *subreq)
{
    errno_t ret;
    int dp_error;
    const char *attrs[] = AD_GPO_ATTRS;

    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ad_gpo_get_sd_referral_state *state =
            tevent_req_data(req, struct ad_gpo_get_sd_referral_state);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Backend is marked offline, retry later!\n");
            tevent_req_done(req);
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Cross-realm GPO processing failed to connect to " \
                   "referred LDAP server: (%d)[%s]\n",
                   ret, sss_strerror(ret));
            tevent_req_error(req, ret);
        }
        return;
    }

    /* Request the referred GPO data */
    subreq = sdap_sd_search_send(state, state->ev, state->opts,
                                 sdap_id_op_handle(state->ref_op),
                                 state->gpo_dn,
                                 SECINFO_DACL,
                                 attrs,
                                 state->timeout);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_sd_search_send failed.\n");
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ad_gpo_get_sd_referral_search_done, req);

}

static void
ad_gpo_get_sd_referral_search_done(struct tevent_req *subreq)
{
    errno_t ret;
    int dp_error;
    size_t num_results, num_refs;
    struct sysdb_attrs **results = NULL;
    char **refs;
    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct ad_gpo_get_sd_referral_state *state =
            tevent_req_data(req, struct ad_gpo_get_sd_referral_state);

    ret = sdap_sd_search_recv(subreq, NULL,
                              &num_results, &results,
                              &num_refs, &refs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        ret = sdap_id_op_done(state->ref_op, ret, &dp_error);

        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get GPO attributes: [%d](%s)\n",
              ret, sss_strerror(ret));
        ret = ENOENT;
        goto done;

    }

    if ((num_results < 1) || (results == NULL)) {
        /* TODO:
         * It's strictly possible for the referral search to return
         * another referral value here, but it shouldn't actually
         * happen with Active Directory. Properly handling (and
         * limiting) the referral chain would be fairly complex, so
         * we will do it later if it ever becomes necessary.
         */
        DEBUG(SSSDBG_OP_FAILURE,
              "No attrs found for referred GPO [%s].\n", state->gpo_dn);
        ret = ENOENT;
        goto done;

    } else if (num_results > 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Received multiple replies\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    state->reply = talloc_steal(state, results[0]);

done:
   talloc_free(results);

   if (ret == EOK) {
       tevent_req_done(req);
   } else if (ret != EAGAIN) {
       tevent_req_error(req, ret);
   }
}

errno_t
ad_gpo_get_sd_referral_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            char **_smb_host,
                            struct sysdb_attrs **_reply)
{
    struct ad_gpo_get_sd_referral_state *state =
                tevent_req_data(req, struct ad_gpo_get_sd_referral_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_smb_host = talloc_steal(mem_ctx, state->smb_host);
    *_reply = talloc_steal(mem_ctx, state->reply);

    return EOK;
}
