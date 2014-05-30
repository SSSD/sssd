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

#include <security/pam_modules.h>
#include <syslog.h>
#include "util/util.h"
#include "util/strtonum.h"
#include "util/child_common.h"
#include "providers/data_provider.h"
#include "providers/dp_backend.h"
#include "providers/ad/ad_access.h"
#include "providers/ad/ad_common.h"
#include "providers/ad/ad_domain_info.h"
#include "providers/ad/ad_gpo.h"
#include "providers/ldap/sdap_access.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_idmap.h"
#include "util/util_sss_idmap.h"
#include <ndr.h>
#include <gen_ndr/security.h>

/* == gpo-ldap constants =================================================== */

#define AD_AT_DN "distinguishedName"
#define AD_AT_UAC "userAccountControl"
#define AD_AT_CONFIG_NC "configurationNamingContext"
#define AD_AT_GPLINK "gPLink"
#define AD_AT_GPOPTIONS "gpOptions"
#define AD_AT_NT_SEC_DESC "nTSecurityDescriptor"
#define AD_AT_CN "cn"
#define AD_AT_DISPLAY_NAME "displayName"
#define AD_AT_FILE_SYS_PATH "gPCFileSysPath"
#define AD_AT_VERSION_NUMBER "versionNumber"
#define AD_AT_MACHINE_EXT_NAMES "gPCMachineExtensionNames"
#define AD_AT_USER_EXT_NAMES "gPCUserExtensionNames"
#define AD_AT_FUNC_VERSION "gPCFunctionalityVersion"
#define AD_AT_FLAGS "flags"

#define UAC_WORKSTATION_TRUST_ACCOUNT 0x00001000
#define AD_AGP_GUID "edacfd8f-ffb3-11d1-b41d-00a0c968f939"
#define AD_AUTHENTICATED_USERS_SID "S-1-5-11"

/* == gpo-smb constants ==================================================== */

#define SMB_STANDARD_URI "smb://"

#define GPO_VERSION_USER(x) (x >> 16)
#define GPO_VERSION_MACHINE(x) (x & 0xffff)

#define GP_EXT_GUID_SECURITY "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"
#define GP_EXT_GUID_SECURITY_SUFFIX "/Microsoft/Windows NT/SecEdit/GptTmpl.inf"

#ifndef SSSD_LIBEXEC_PATH
#error "SSSD_LIBEXEC_PATH not defined"
#else
#define GPO_CHILD SSSD_LIBEXEC_PATH"/gpo_child"
#endif

/* fd used by the gpo_child process for logging */
int gpo_child_debug_fd = -1;

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
    const char *gpo_display_name;
    const char *gpo_file_sys_path;
    uint32_t gpo_container_version;
    const char **gpo_cse_guids;
    int num_gpo_cse_guids;
    int gpo_func_version;
    int gpo_flags;
};

enum ace_eval_status {
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
                                           int timeout,
                                           const char *target_dn,
                                           const char *domain_name);
int ad_gpo_process_som_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            struct gp_som ***som_list);

struct tevent_req *ad_gpo_process_gpo_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct sdap_id_op *sdap_op,
                                           struct sdap_options *opts,
                                           char *server_hostname,
                                           int timeout,
                                           struct gp_som **som_list);
int ad_gpo_process_gpo_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            struct gp_gpo ***candidate_gpos,
                            int *num_candidate_gpos);
struct tevent_req *ad_gpo_process_cse_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           char *smb_uri);
int ad_gpo_process_cse_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            int *_allowed_size,
                            char ***_allowed_sids,
                            int *_denied_size,
                            char ***_denied_sids);

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
        return ret;
    }

    if (res->count == 0) {
        ret = ENOENT;
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_initgroups returned empty result\n");
        return ret;
    }

    user_sid = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SID_STR, NULL);
    num_group_sids = (res->count) - 1;

    /* include space for AD_AUTHENTICATED_USERS_SID and NULL */
    group_sids = talloc_array(tmp_ctx, const char *, num_group_sids + 1 + 1);
    if (group_sids == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_group_sids; i++) {
        group_sid = ldb_msg_find_attr_as_string(res->msgs[i+1],
                                                SYSDB_SID_STR, NULL);
        if (group_sid == NULL) {
            continue;
        }

        group_sids[i] = talloc_steal(group_sids, group_sid);
        if (group_sids[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }
    group_sids[i++] = talloc_strdup(group_sids, AD_AUTHENTICATED_USERS_SID);
    group_sids[i] = NULL;

    *_group_size = num_group_sids + 1;
    *_group_sids = talloc_steal(mem_ctx, group_sids);
    *_user_sid = talloc_steal(mem_ctx, user_sid);
    return EOK;

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
                               const char **group_sids,
                               int group_size,
                               struct dom_sid ace_dom_sid,
                               struct sss_idmap_ctx *idmap_ctx,
                               bool *_included)
{
    int i = 0;
    struct dom_sid *user_dom_sid;
    struct dom_sid *group_dom_sid;
    enum idmap_error_code err;
    bool included = false;

    err = sss_idmap_sid_to_smb_sid(idmap_ctx, user_sid, &user_dom_sid);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to initialize idmap context.\n");
        return EFAULT;
    }

    included = ad_gpo_dom_sid_equal(&ace_dom_sid, user_dom_sid);
    sss_idmap_free_smb_sid(idmap_ctx, user_dom_sid);
    if (included) {
        *_included = true;
        return EOK;
    }

    for (i = 0; i < group_size; i++) {
        err = sss_idmap_sid_to_smb_sid(idmap_ctx, group_sids[i], &group_dom_sid);
        if (err != IDMAP_SUCCESS) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to initialize idmap context.\n");
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
 * This function determines whether use of the extended right
 * named "ApplyGroupPolicy" (AGP) is allowed, by comparing the specified
 * user_sid and group_sids against the specified access control entry (ACE).
 * This function returns ALLOWED, DENIED, or NEUTRAL depending on whether
 * the ACE explictly allows, explicitly denies, or does neither.
 *
 * Note that the 'M' abbreviation used in the evaluation algorithm stands for
 * "access_mask", which represents the set of access rights associated with an
 * individual ACE. The access right of interest to the GPO code is
 * RIGHT_DS_CONTROL_ACCESS, which serves as a container for all control access
 * rights. The specific control access right is identified by a GUID in the
 * ACE's ObjectType. In our case, this is the GUID corresponding to AGP.
 *
 * The ACE evaluation algorithm is specified in [MS-ADTS] 5.1.3.3.4:
 * - Deny access by default
 * - If the "Inherit Only" (IO) flag is set in the ACE, skip the ACE.
 * - If the SID in the ACE does not match any SID in the requester's
 *   security context, skip the ACE
 * - If the ACE type is "Object Access Allowed", the access right
 *   RIGHT_DS_CONTROL_ACCESS (CR) is present in M, and the ObjectType
 *   field in the ACE is either not present OR contains a GUID value equal
 *   to AGP, then grant requested control access right. Stop access checking.
 * - If the ACE type is "Object Access Denied", the access right
 *   RIGHT_DS_CONTROL_ACCESS (CR) is present in M, and the ObjectType
 *   field in the ACE is either not present OR contains a GUID value equal to
 *   AGP, then deny the requested control access right. Stop access checking.
 */
static enum ace_eval_status ad_gpo_evaluate_ace(struct security_ace *ace,
                                                struct sss_idmap_ctx *idmap_ctx,
                                                const char *user_sid,
                                                const char **group_sids,
                                                int group_size)
{
    bool agp_included = false;
    bool included = false;
    int ret = 0;
    struct security_ace_object object;
    struct GUID ext_right_agp_guid;

    if (ace->flags & SEC_ACE_FLAG_INHERIT_ONLY) {
        return AD_GPO_ACE_NEUTRAL;
    }

    ret = ad_gpo_ace_includes_client_sid(user_sid, group_sids, group_size,
                                         ace->trustee, idmap_ctx, &included);

    if (ret != EOK) {
        return AD_GPO_ACE_DENIED;
    }

    if (!included) {
        return AD_GPO_ACE_NEUTRAL;
    }

    object = ace->object.object;
    GUID_from_string(AD_AGP_GUID, &ext_right_agp_guid);

    if (object.flags & SEC_ACE_OBJECT_TYPE_PRESENT) {
        if (GUID_equal(&object.type.type, &ext_right_agp_guid)) {
            agp_included = true;
        }
    } else {
        agp_included = false;
    }

    if (ace->access_mask & SEC_ADS_CONTROL_ACCESS) {
        if (agp_included) {
            if (ace->type == SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT) {
                return AD_GPO_ACE_ALLOWED;
            } else if (ace->type == SEC_ACE_TYPE_ACCESS_DENIED_OBJECT) {
                return AD_GPO_ACE_DENIED;
            }
        }
    }

    return AD_GPO_ACE_DENIED;
}

/*
 * This function extracts the GPO's DACL (discretionary access control list)
 * from the GPO's specified security descriptor, and determines whether
 * the GPO is applicable to the policy target, by comparing the specified
 * user_sid and group_sids against each access control entry (ACE) in the DACL.
 * The boolean result is assigned to the _access_allowed output parameter.
 */
static errno_t ad_gpo_evaluate_dacl(struct security_acl *dacl,
                                    struct sss_idmap_ctx *idmap_ctx,
                                    const char *user_sid,
                                    const char **group_sids,
                                    int group_size,
                                    bool *_dacl_access_allowed)
{
    uint32_t num_aces = 0;
    enum ace_eval_status ace_status;
    int i = 0;
    struct security_ace *ace = NULL;

    num_aces = dacl->num_aces;

    /*
     * [MS-ADTS] 5.1.3.3.4:
     * If the DACL does not have any ACE, then deny the requester the
     * requested control access right.
     */
    if (num_aces == 0) {
        *_dacl_access_allowed = false;
        return EOK;
    }

    for (i = 0; i < dacl->num_aces; i ++) {
        ace = &dacl->aces[i];

        ace_status = ad_gpo_evaluate_ace(ace, idmap_ctx, user_sid,
                                         group_sids, group_size);

        switch (ace_status) {
        case AD_GPO_ACE_NEUTRAL:
            continue;
        case AD_GPO_ACE_ALLOWED:
            *_dacl_access_allowed = true;
            return EOK;
        case AD_GPO_ACE_DENIED:
            *_dacl_access_allowed = false;
            return EOK;
        }
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
                           struct sss_domain_info *domain,
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
    int gpo_dn_idx = 0;
    bool access_allowed = false;
    struct gp_gpo **dacl_filtered_gpos = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ad_gpo_get_sids(tmp_ctx, user, domain, &user_sid,
                          &group_sids, &group_size);
    if (ret != EOK) {
        ret = ERR_NO_SIDS;
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to retrieve SIDs: [%d](%s)\n", ret, sss_strerror(ret));
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
        sd = candidate_gpo->gpo_sd;
        dacl = candidate_gpo->gpo_sd->dacl;

        DEBUG(SSSDBG_TRACE_ALL, "examining dacl candidate_gpo_guid:%s\n",
                                candidate_gpo->gpo_guid);

        /* gpo_func_version must be set to version 2 */
        if (candidate_gpo->gpo_func_version != 2) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "GPO not applicable to target per security filtering\n");
            continue;
        }

        /* gpo_flags value of 2 means that GPO's computer portion is disabled */
        if (candidate_gpo->gpo_flags == 2) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "GPO not applicable to target per security filtering\n");
            continue;
        }

        /*
         * [MS-ADTS] 5.1.3.3.4:
         * If the security descriptor has no DACL or its "DACL Present" bit
         * is not set, then grant requester the requested control access right.
         */

        if ((!(sd->type & SEC_DESC_DACL_PRESENT)) || (dacl == NULL)) {
            DEBUG(SSSDBG_TRACE_ALL, "DACL is not present\n");
            access_allowed = true;
            break;
        }

        ad_gpo_evaluate_dacl(dacl, idmap_ctx, user_sid, group_sids,
                             group_size, &access_allowed);
        if (access_allowed) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "GPO applicable to target per security filtering\n");
            dacl_filtered_gpos[gpo_dn_idx] = talloc_steal(dacl_filtered_gpos,
                                                          candidate_gpo);
            gpo_dn_idx++;
        } else {
            DEBUG(SSSDBG_TRACE_ALL,
                  "GPO not applicable to target per security filtering\n");
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
 * This cse-specific function (GP_EXT_GUID_SECURITY) populates the output
 * parameter (found) based on whether the input user_sid or any of the input
 * group_sids appear in the input list of privilege_sids.
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
 * This cse-specific function (GP_EXT_GUID_SECURITY) performs HBAC policy
 * application and determines whether logon access is granted or denied for
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
 * settings is unaffected by them (b/c the absence of allowed_sids grants access).
 *
 * Note that if a principal_sid appears in both allowed_sids and denied_sids,
 * the "allowed_sids_condition" is met, but the "denied_sids_condition" is not.
 * In other words, Deny takes precedence over Allow.
 */
static errno_t
ad_gpo_access_check(TALLOC_CTX *mem_ctx,
                    enum gpo_access_control_mode gpo_mode,
                    const char *user,
                    struct sss_domain_info *domain,
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

    DEBUG(SSSDBG_TRACE_FUNC, "POLICY FILE:\n");
    DEBUG(SSSDBG_TRACE_FUNC, "allowed_size = %d\n", allowed_size);
    for (j= 0; j < allowed_size; j++) {
        DEBUG(SSSDBG_TRACE_FUNC, "allowed_sids[%d] = %s\n", j,
              allowed_sids[j]);
    }

    DEBUG(SSSDBG_TRACE_FUNC, "denied_size = %d\n", denied_size);
    for (j= 0; j < denied_size; j++) {
        DEBUG(SSSDBG_TRACE_FUNC, " denied_sids[%d] = %s\n", j,
              denied_sids[j]);
    }

    ret = ad_gpo_get_sids(mem_ctx, user, domain, &user_sid,
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

    /* If AllowLogonLocally is not defined, all users are allowed */
    if (allowed_size == 0) {
        access_granted = true;
    }  else {
        access_granted = check_rights(allowed_sids, allowed_size, user_sid,
                                      group_sids, group_size);
    }

    DEBUG(SSSDBG_TRACE_FUNC, " access_granted = %d\n", access_granted);

    access_denied = check_rights(denied_sids, denied_size, user_sid,
                                 group_sids, group_size);
    DEBUG(SSSDBG_TRACE_FUNC, "  access_denied = %d\n", access_denied);

    if (access_granted && !access_denied) {
        return EOK;
    } else {
        switch (gpo_mode) {
        case GPO_ACCESS_CONTROL_ENFORCING:
            return EACCES;
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

#define GPO_CHILD_LOG_FILE "gpo_child"
static errno_t gpo_child_init(void)
{
    int ret;
    FILE *debug_filep;

    if (debug_to_file != 0 && gpo_child_debug_fd == -1) {
        ret = open_debug_file_ex(GPO_CHILD_LOG_FILE, &debug_filep, false);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Error setting up logging (%d) [%s]\n",
                        ret, strerror(ret));
            return ret;
        }

        gpo_child_debug_fd = fileno(debug_filep);
        if (gpo_child_debug_fd == -1) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "fileno failed [%d][%s]\n", errno, strerror(errno));
            ret = errno;
            return ret;
        }
    }

    return EOK;
}

/* == ad_gpo_access_send/recv implementation ================================*/

struct ad_gpo_access_state {
    struct tevent_context *ev;
    struct ldb_context *ldb_ctx;
    struct sdap_id_conn_ctx *conn;
    struct sdap_id_op *sdap_op;
    char *server_hostname;
    struct sdap_options *opts;
    int timeout;
    struct sss_domain_info *domain;
    const char *user;
    enum gpo_access_control_mode gpo_mode;
    const char *ad_hostname;
    const char *target_dn;
    struct gp_gpo **dacl_filtered_gpos;
    int num_dacl_filtered_gpos;
    struct gp_gpo **cse_filtered_gpos;
    int num_cse_filtered_gpos;
    int cse_gpo_index;
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
                   const char *user)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ad_gpo_access_state *state;
    char *server_uri;
    LDAPURLDesc *lud;
    errno_t ret;

    /* setup logging for gpo child */
    gpo_child_init();

    req = tevent_req_create(mem_ctx, &state, struct ad_gpo_access_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->domain = domain;
    state->dacl_filtered_gpos = NULL;
    state->num_dacl_filtered_gpos = 0;
    state->cse_filtered_gpos = NULL;
    state->num_cse_filtered_gpos = 0;
    state->cse_gpo_index = -1;
    state->ev = ev;
    state->user = user;
    state->ldb_ctx = sysdb_ctx_get_ldb(domain->sysdb);
    state->gpo_mode = ctx->gpo_access_control_mode;
    state->ad_hostname = dp_opt_get_string(ctx->ad_options, AD_HOSTNAME);
    state->opts = ctx->sdap_access_ctx->id_ctx->opts;
    state->timeout = dp_opt_get_int(state->opts->basic, SDAP_SEARCH_TIMEOUT);
    state->conn = ad_get_dom_ldap_conn(ctx->ad_id_ctx, domain);
    state->sdap_op = sdap_id_op_create(state, state->conn->conn_cache);
    if (state->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed.\n");
        ret = ENOMEM;
        goto immediately;
    }

    /* extract server_hostname from server_uri */
    server_uri = state->conn->service->uri;
    ret = ldap_url_parse(server_uri, &lud);
    if (ret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to parse ldap URI (%s)!\n", server_uri);
        ret = EINVAL;
        goto immediately;
    }

    if (lud->lud_host == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "The LDAP URI (%s) did not contain a host name\n", server_uri);
        ldap_free_urldesc(lud);
        ret = EINVAL;
        goto immediately;
    }

    state->server_hostname = talloc_strdup(state, lud->lud_host);
    ldap_free_urldesc(lud);
    if (!state->server_hostname) {
        ret = ENOMEM;
        goto immediately;
    }
    DEBUG(SSSDBG_TRACE_ALL, "server_hostname from uri: %s\n",
          state->server_hostname);

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sdap_id_op_connect_send failed: [%d](%s)\n",
               ret, sss_strerror(ret));
        goto immediately;
    }
    tevent_req_set_callback(subreq, ad_gpo_connect_done, req);

    ret = EOK;

immediately:

    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void
ad_gpo_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_access_state *state;
    char* filter;
    char *sam_account_name;
    char *domain_dn;
    int dp_error;
    errno_t ret;

    const char *attrs[] = {AD_AT_DN, AD_AT_UAC, NULL};

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_access_state);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        /* TBD: handle (dp_error == DP_ERR_OFFLINE) case */

        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to connect to AD server: [%d](%s)\n",
               ret, sss_strerror(ret));

        tevent_req_error(req, ret);
        return;
    }

    sam_account_name = talloc_asprintf(state, "%s$", state->ad_hostname);
    if (sam_account_name == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "sam_account_name is %s\n", sam_account_name);

    /* Convert the domain name into domain DN */
    ret = domain_to_basedn(state, state->domain->name, &domain_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot convert domain name [%s] to base DN [%d]: %s\n",
               state->domain->name, ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    /* SDAP_OC_USER objectclass covers both users and computers */
    filter = talloc_asprintf(state,
                             "(&(objectclass=%s)(%s=%s))",
                             state->opts->user_map[SDAP_OC_USER].name,
                             state->opts->user_map[SDAP_AT_USER_NAME].name,
                             sam_account_name);

    if (filter == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    subreq = sdap_get_generic_send(state, state->ev, state->opts,
                                   sdap_id_op_handle(state->sdap_op),
                                   domain_dn, LDAP_SCOPE_SUBTREE,
                                   filter, attrs, NULL, 0,
                                   state->timeout,
                                   false);

    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send failed.\n");
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_set_callback(subreq, ad_gpo_target_dn_retrieval_done, req);
}

static void
ad_gpo_target_dn_retrieval_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_access_state *state;
    int ret;
    int dp_error;
    size_t reply_count;
    struct sysdb_attrs **reply;
    const char *target_dn = NULL;
    uint32_t uac;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_access_state);
    ret = sdap_get_generic_recv(subreq, state,
                                &reply_count, &reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);
        /* TBD: handle (dp_error == DP_ERR_OFFLINE) case */

        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get policy target's DN: [%d](%s)\n",
               ret, sss_strerror(ret));
        ret = ENOENT;
        goto done;
    }

    /* make sure there is only one non-NULL reply returned */

    if (reply_count < 1) {
        DEBUG(SSSDBG_OP_FAILURE, "No DN retrieved for policy target.\n");
        ret = ENOENT;
        goto done;
    } else if (reply_count > 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Multiple replies for policy target\n");
        ret = ERR_INTERNAL;
        goto done;
    } else if (reply == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "reply_count is 1, but reply is NULL\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    /* reply[0] holds requested attributes of single reply */
    ret = sysdb_attrs_get_string(reply[0], AD_AT_DN, &target_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_attrs_get_string failed: [%d](%s)\n",
               ret, sss_strerror(ret));
        goto done;
    }
    state->target_dn = talloc_steal(state, target_dn);
    if (state->target_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_get_uint32_t(reply[0], AD_AT_UAC, &uac);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_attrs_get_uint32_t failed: [%d](%s)\n",
               ret, sss_strerror(ret));
        goto done;
    }

    /* we only support computer policy targets, not users */
    if (!(uac & UAC_WORKSTATION_TRUST_ACCOUNT)) {
        ret = EINVAL;
        goto done;
    }

    subreq = ad_gpo_process_som_send(state,
                                     state->ev,
                                     state->conn,
                                     state->ldb_ctx,
                                     state->sdap_op,
                                     state->opts,
                                     state->timeout,
                                     state->target_dn,
                                     state->domain->name);
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
 * This function then sends each cse_filtered_gpo to the CSE processing engine
 * for policy application, which currently consists of HBAC functionality.
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

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_access_state);
    ret = ad_gpo_process_gpo_recv(subreq, state, &candidate_gpos,
                                  &num_candidate_gpos);

    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);

    if (ret != EOK) {
        /* TBD: handle (dp_error == DP_ERR_OFFLINE) case */

        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get GPO list: [%d](%s)\n",
              ret, sss_strerror(ret));
        ret = ENOENT;
        goto done;
    }

    ret = ad_gpo_filter_gpos_by_dacl(state, state->user, state->domain,
                                     state->opts->idmap_ctx->map,
                                     candidate_gpos, num_candidate_gpos,
                                     &state->dacl_filtered_gpos,
                                     &state->num_dacl_filtered_gpos);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to filter GPO list by DACKL: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (state->dacl_filtered_gpos[0] == NULL) {
        /* since no applicable gpos were found, there is nothing to enforce */
        DEBUG(SSSDBG_TRACE_FUNC,
              "no applicable gpos found after dacl filtering\n");
        ret = EOK;
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
               ret, strerror(ret));
        goto done;
    }

    if (state->cse_filtered_gpos[0] == NULL) {
        /* no gpos contain "SecuritySettings" cse_guid, nothing to enforce */
        DEBUG(SSSDBG_TRACE_FUNC,
              "no applicable gpos found after cse_guid filtering\n");
        ret = EOK;
        goto done;
    }

    for (i = 0; i < state->num_cse_filtered_gpos; i++) {
        DEBUG(SSSDBG_TRACE_FUNC, "cse_filtered_gpos[%d]->gpo_guid is %s\n", i,
                                  state->cse_filtered_gpos[i]->gpo_guid);
    }

    DEBUG(SSSDBG_TRACE_FUNC, "num_cse_filtered_gpos: %d\n",
          state->num_cse_filtered_gpos);

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
    char *smb_uri;
    int i = 0;

    state = tevent_req_data(req, struct ad_gpo_access_state);

    state->cse_gpo_index++;
    struct gp_gpo *cse_filtered_gpo =
        state->cse_filtered_gpos[state->cse_gpo_index];

    /* cse_filtered_gpo is NULL only after all GPOs have been processed */
    if (cse_filtered_gpo == NULL) return EOK;

    DEBUG(SSSDBG_TRACE_FUNC, "cse filtered_gpos[%d]->gpo_guid is %s\n",
          state->cse_gpo_index, cse_filtered_gpo->gpo_guid);
    DEBUG(SSSDBG_TRACE_FUNC, "cse filtered_gpos[%d]->file_sys_path is %s\n",
          state->cse_gpo_index, cse_filtered_gpo->gpo_file_sys_path);
    for (i = 0; i < cse_filtered_gpo->num_gpo_cse_guids; i++) {
        DEBUG(SSSDBG_TRACE_ALL,
              "cse_filtered_gpos[%d]->gpo_cse_guids[%d]->gpo_guid is %s\n",
              state->cse_gpo_index, i, cse_filtered_gpo->gpo_cse_guids[i]);
    }

    smb_uri = talloc_asprintf(state, "%s%s",
                              cse_filtered_gpo->gpo_file_sys_path,
                              GP_EXT_GUID_SECURITY_SUFFIX);

    subreq = ad_gpo_process_cse_send(state, state->ev, smb_uri);

    tevent_req_set_callback(subreq, ad_gpo_cse_done, req);
    return EAGAIN;
}

/*
 * This cse-specific function (GP_EXT_GUID_SECURITY) retrieves a list of
 * allowed_sids and denied_sids, and uses them to determine whether logon
 * access is granted or denied for the state's {user, domain} tuple.
 *
 * If it is determined that the current cse_filtered_gpo grants access, then
 * we process the next cse_filtered_gpo in the list. At any time, if access is
 * denied, we return immediately with an error.
 */
static void
ad_gpo_cse_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_access_state *state;
    int ret;
    char **allowed_sids;
    int allowed_size;
    char **denied_sids;
    int denied_size;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_access_state);

    ret = ad_gpo_process_cse_recv(subreq, state, &allowed_size, &allowed_sids,
                                  &denied_size, &denied_sids);

    talloc_zfree(subreq);

    if (ret != EOK) {
        /* TBD: handle ret error  */
        goto done;
    }

    /* TBD: allowed/denied_sids/size, should be retrieved from cache */
    ret = ad_gpo_access_check
        (state, state->gpo_mode, state->user, state->domain,
         allowed_sids, allowed_size, denied_sids, denied_size);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "GPO access check failed: [%d](%s)\n",
              ret, strerror(ret));
        goto done;
    }

    ret = ad_gpo_cse_step(req);

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
    tmp_dn = target_dn;;
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

    DEBUG(SSSDBG_TRACE_ALL, "som_dn: %s\n", som_dn);
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
        ret = EINVAL;
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
    state->timeout = timeout;
    state->som_index = -1;
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

    subreq = ad_master_domain_send(state, state->ev, conn,
                                   state->sdap_op, domain_name);

    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ad_master_domain_send failed.\n");
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
    char *site;
    const char *attrs[] = {AD_AT_CONFIG_NC, NULL};

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_process_som_state);

    /* gpo code only cares about the site name */
    ret = ad_master_domain_recv(subreq, state, NULL, NULL, &site, NULL);
    talloc_zfree(subreq);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot retrieve master domain info\n");
        tevent_req_error(req, ENOENT);
        return;
    }

    state->site_name = talloc_asprintf(state, "cn=%s", site);
    if (state->site_name == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

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
        /* TBD: handle (dp_error == DP_ERR_OFFLINE) case */

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

    state->som_index++;
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
        /* TBD: handle (dp_error == DP_ERR_OFFLINE) case */

        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get SOM attributes: [%d](%s)\n",
              ret, sss_strerror(ret));
        ret = ENOENT;
        goto done;
    }
    if ((num_results < 1) || (results == NULL)) {
        DEBUG(SSSDBG_OP_FAILURE, "no attrs found for SOM; try next SOM.\n");
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
        DEBUG(SSSDBG_OP_FAILURE, "no attrs found for SOM; try next SOM\n");
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
 *   (i.e. 1st GPO linked to SOM is applied after 2nd GPO linked to SOM, etc).
 * - enforced GPOs are applied after unenforced GPOs.
 *
 * As such, the _candidate_gpos output's dn fields looks like (in link order):
 * [unenforced {Site, Domain, OU}; enforced {Site, Domain, OU}]
 *
 * Note that in the case of conflicting policy settings, GPOs appearing later
 * in the list will trump GPOs appearing earlier in the list.
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

    i = 0;
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
                enforced_gpo_dns[enforced_idx] =
                    talloc_steal(enforced_gpo_dns, gp_gplink->gpo_dn);
                if (enforced_gpo_dns[enforced_idx] == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
                enforced_idx++;
            } else {

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
    for (i = num_unenforced - 1; i >= 0; i--) {
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
 * This function converts the input_path to an smb uri, which is used to
 * populate the _converted_path output parameter. The output is constructed by
 * concatenating the following elements:
 * - SMB_STANDARD_URI ("smb://")
 * - server_hostname (which replaces domain_name in input path)
 * - smb_path (which starts with the slash immediately after the domain name
 * Additionally, each forward slash ('\') is replaced with a back slash ('/')
 *
 * Example: if input_path = "\\foo.com\SysVol\foo.com\..." and
 * server_hostname = "adserver.foo.com", then _converted_path would be
 * "smb://adserver.foo.com/SysVol/foo.com/..."
 *
 * Note that the input_path must have at least three forward slash separators.
 * For example, input_path = "\\foo.com" is not a valid input_path, because
 * it has only two forward slash separators.
 */
static errno_t
ad_gpo_convert_to_smb_uri(TALLOC_CTX *mem_ctx,
                          char *server_hostname,
                          char *input_path,
                          const char **_converted_path)
{
    char *ptr;
    const char delim = '\\';
    int ret;
    int num_seps = 0;
    char *smb_path = NULL;

    DEBUG(SSSDBG_TRACE_ALL, "input_path: %s\n", input_path);

    if (input_path == NULL ||
        *input_path == '\0' ||
        _converted_path == NULL) {
        ret = EINVAL;
        goto done;
    }

    ptr = input_path;
    while ((ptr = strchr(ptr, delim))) {
        num_seps++;
        if (num_seps == 3) {
            /* keep track of path from third slash onwards (after domain name) */
            smb_path = ptr;
        }
        *ptr = '/';
        ptr++;
    }

    if (num_seps == 0) {
        ret = EINVAL;
        goto done;
    }

    if (smb_path == NULL) {
        ret = EINVAL;
        goto done;
    }

    *_converted_path = talloc_asprintf(mem_ctx, "%s%s%s",
                                       SMB_STANDARD_URI,
                                       server_hostname,
                                       smb_path);
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
    struct tevent_context *ev;
    struct sdap_id_op *sdap_op;
    struct sdap_options *opts;
    char *server_hostname;
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
    state->opts = opts;
    state->server_hostname = server_hostname;
    state->timeout = timeout;
    state->gpo_index = -1;
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
        ret = ENOENT;
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
    const char *attrs[] = {AD_AT_NT_SEC_DESC, AD_AT_CN, AD_AT_DISPLAY_NAME,
                           AD_AT_FILE_SYS_PATH, AD_AT_VERSION_NUMBER,
                           AD_AT_MACHINE_EXT_NAMES, AD_AT_FUNC_VERSION,
                           AD_AT_FLAGS, NULL};
    struct tevent_req *subreq;
    struct ad_gpo_process_gpo_state *state;

    state = tevent_req_data(req, struct ad_gpo_process_gpo_state);

    state->gpo_index++;
    struct gp_gpo *gp_gpo = state->candidate_gpos[state->gpo_index];

    /* gp_gpo is NULL only after all GPOs have been processed */
    if (gp_gpo == NULL) return EOK;

    const char *gpo_dn = gp_gpo->gpo_dn;

    subreq = sdap_sd_search_send(state, state->ev,
                                 state->opts, sdap_id_op_handle(state->sdap_op),
                                 gpo_dn, SECINFO_DACL, attrs, state->timeout);

    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send failed.\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ad_gpo_get_gpo_attrs_done, req);
    return EAGAIN;
}

static void
ad_gpo_get_gpo_attrs_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_process_gpo_state *state;
    int ret;
    int dp_error;
    size_t num_results;
    struct sysdb_attrs **results;
    struct ldb_message_element *el = NULL;
    const char *gpo_guid = NULL;
    const char *smb_uri = NULL;
    const char *gpo_display_name = NULL;
    const char *raw_file_sys_path = NULL;
    char *file_sys_path = NULL;
    uint8_t *raw_machine_ext_names = NULL;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_process_gpo_state);

    ret = sdap_sd_search_recv(subreq, state, &num_results, &results);
    talloc_zfree(subreq);

    if (ret != EOK) {
        ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);
        /* TBD: handle (dp_error == DP_ERR_OFFLINE) case */

        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get GPO attributes: [%d](%s)\n",
              ret, sss_strerror(ret));
        ret = ENOENT;
        goto done;
    }

    if ((num_results < 1) || (results == NULL)) {
        DEBUG(SSSDBG_OP_FAILURE, "no attrs found for GPO; try next GPO.\n");
        ret = ad_gpo_get_gpo_attrs_step(req);
        goto done;
    }
    else if (num_results > 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Received multiple replies\n");
        ret = ERR_INTERNAL;
        goto done;
    }

    struct gp_gpo *gp_gpo = state->candidate_gpos[state->gpo_index];

    /* retrieve AD_AT_CN */
    ret = sysdb_attrs_get_string(results[0], AD_AT_CN, &gpo_guid);
    if (ret != EOK) {
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

    /* retrieve AD_AT_DISPLAY_NAME */
    ret = sysdb_attrs_get_string(results[0], AD_AT_DISPLAY_NAME,
                                 &gpo_display_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_attrs_get_string failed: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto done;
    }

    gp_gpo->gpo_display_name = talloc_steal(gp_gpo, gpo_display_name);
    if (gp_gpo->gpo_display_name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "gpo_display_name: %s\n",
                            gp_gpo->gpo_display_name);

    /* retrieve AD_AT_FILE_SYS_PATH */
    ret = sysdb_attrs_get_string(results[0],
                                 AD_AT_FILE_SYS_PATH,
                                 &raw_file_sys_path);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_attrs_get_string failed: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto done;
    }

    file_sys_path = talloc_strdup(gp_gpo, raw_file_sys_path);
    ad_gpo_convert_to_smb_uri(state, state->server_hostname, file_sys_path,
                              &smb_uri);

    gp_gpo->gpo_file_sys_path = talloc_asprintf(gp_gpo, "%s/Machine",
                                                smb_uri);
    if (gp_gpo->gpo_file_sys_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "gpo_file_sys_path: %s\n",
          gp_gpo->gpo_file_sys_path);

    /* retrieve AD_AT_VERSION_NUMBER */
    ret = sysdb_attrs_get_uint32_t(results[0], AD_AT_VERSION_NUMBER,
                                   &gp_gpo->gpo_container_version);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_attrs_get_uint32_t failed: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "gpo_container_version: %d\n",
                            gp_gpo->gpo_container_version);

    /* retrieve AD_AT_MACHINE_EXT_NAMES */
    ret = sysdb_attrs_get_el(results[0], AD_AT_MACHINE_EXT_NAMES, &el);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_el() failed\n");
        goto done;
    }
    if ((ret == ENOENT) || (el->num_values == 0)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "machine_ext_names not found or has no value\n");
        ret = ENOENT;
        goto done;
    }

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

    /* retrieve AD_AT_FUNC_VERSION */
    ret = sysdb_attrs_get_int32_t(results[0], AD_AT_FUNC_VERSION,
                                  &gp_gpo->gpo_func_version);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_attrs_get_int32_t failed: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "gpo_func_version: %d\n",
                            gp_gpo->gpo_func_version);

    /* retrieve AD_AT_FLAGS */
    ret = sysdb_attrs_get_int32_t(results[0], AD_AT_FLAGS,
                                  &gp_gpo->gpo_flags);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sysdb_attrs_get_int32_t failed: [%d](%s)\n",
              ret, sss_strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "gpo_flags: %d\n", gp_gpo->gpo_flags);

    /* retrieve AD_AT_NT_SEC_DESC */
    ret = sysdb_attrs_get_el(results[0], AD_AT_NT_SEC_DESC, &el);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_el() failed\n");
        goto done;
    }
    if ((ret == ENOENT) || (el->num_values == 0)) {
        DEBUG(SSSDBG_OP_FAILURE,
              "nt_sec_desc attribute not found or has no value\n");
        ret = ENOENT;
        goto done;
    }

    ret = ad_gpo_parse_sd(gp_gpo, el[0].values[0].data, el[0].values[0].length,
                          &gp_gpo->gpo_sd);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ad_gpo_parse_sd() failed\n");
        goto done;
    }

    ret = ad_gpo_get_gpo_attrs_step(req);

 done:

    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }
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
                       char *smb_uri,
                       struct io_buffer **io_buf)
{
    struct io_buffer *buf;
    size_t rp;
    int smb_uri_length;

    smb_uri_length = strlen(smb_uri);

    DEBUG(SSSDBG_TRACE_FUNC, "smb_uri: %s\n", smb_uri);
    DEBUG(SSSDBG_TRACE_FUNC, "strlen(smb_uri): %d\n", smb_uri_length);

    buf = talloc(mem_ctx, struct io_buffer);
    if (buf == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
        return ENOMEM;
    }

    buf->size = 1 * sizeof(uint32_t);
    buf->size += smb_uri_length;

    DEBUG(SSSDBG_TRACE_ALL, "buffer size: %zu\n", buf->size);

    buf->data = talloc_size(buf, buf->size);
    if (buf->data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        talloc_free(buf);
        return ENOMEM;
    }

    rp = 0;
    /* smb_uri */
    SAFEALIGN_SET_UINT32(&buf->data[rp], smb_uri_length, &rp);
    safealign_memcpy(&buf->data[rp], smb_uri, smb_uri_length, &rp);

    *io_buf = buf;
    return EOK;
}

static errno_t
parse_gpo_child_response(TALLOC_CTX *mem_ctx,
                         uint8_t *buf, ssize_t size,
                         char ***_allowed_sids,
                         int *_allowed_size,
                         char ***_denied_sids,
                         int *_denied_size)
{
    size_t p = 0;
    uint32_t res;
    errno_t ret;
    int allowed_size = 0;
    int denied_size = 0;
    int i = 0;
    int sid_len = 0;
    char **allowed_sids;
    char **denied_sids;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* operation result code */
    SAFEALIGN_COPY_UINT32_CHECK(&res, buf + p, size, &p);

    /* allowed_size */
    SAFEALIGN_COPY_UINT32_CHECK(&allowed_size, buf + p, size, &p);
    DEBUG(SSSDBG_TRACE_FUNC, "child response allowed_size: %d\n", allowed_size);

    allowed_sids = talloc_array(tmp_ctx, char *, allowed_size);
    if (allowed_sids == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < allowed_size; i++) {
        SAFEALIGN_COPY_UINT32_CHECK(&sid_len, buf + p, size, &p);
        if ((p + sid_len ) > size) {
            ret = EINVAL;
            goto done;
        }
        allowed_sids[i] = talloc_strndup(allowed_sids,
                                         (const char *)buf + p,
                                         sid_len);
        if (allowed_sids[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
        p += sid_len;
    }

    /* denied_size */
    SAFEALIGN_COPY_UINT32_CHECK(&denied_size, buf + p, size, &p);
    DEBUG(SSSDBG_TRACE_FUNC, "child response denied_size: %d\n", denied_size);

    denied_sids = talloc_array(tmp_ctx, char *, denied_size);
    if (denied_sids == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < denied_size; i++) {
        SAFEALIGN_COPY_UINT32_CHECK(&sid_len, buf + p, size, &p);
        if ((p + sid_len ) > size) {
            ret = EINVAL;
            goto done;
        }
        denied_sids[i] = talloc_strndup(denied_sids,
                                        (const char *)buf + p,
                                        sid_len);
        if (denied_sids[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
        p += sid_len;
    }

    *_allowed_size = allowed_size;
    *_allowed_sids = talloc_steal(mem_ctx, allowed_sids);
    *_denied_size = denied_size;
    *_denied_sids = talloc_steal(mem_ctx, denied_sids);

    ret = EOK;

 done:
    talloc_free(tmp_ctx);
    return ret;
}

/* == ad_gpo_process_cse_send/recv implementation ========================== */

struct ad_gpo_process_cse_state {
    struct tevent_context *ev;
    pid_t child_pid;
    uint8_t *buf;
    ssize_t len;
    struct io *io;
};

struct io {
    int read_from_child_fd;
    int write_to_child_fd;
};

static errno_t
gpo_child_io_destructor(void *ptr)
{
    int ret;
    struct io *io;

    io = talloc_get_type(ptr, struct io);
    if (io == NULL) return EOK;

    if (io->write_to_child_fd != -1) {
        ret = close(io->write_to_child_fd);
        io->write_to_child_fd = -1;
        if (ret != EOK) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "close failed [%d][%s].\n", ret, strerror(ret));
        }
    }

    if (io->read_from_child_fd != -1) {
        ret = close(io->read_from_child_fd);
        io->read_from_child_fd = -1;
        if (ret != EOK) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "close failed [%d][%s].\n", ret, strerror(ret));
        }
    }

    return EOK;
}

static errno_t gpo_fork_child(struct tevent_req *req);
static void gpo_cse_step(struct tevent_req *subreq);
static void gpo_cse_done(struct tevent_req *subreq);

/*
 * This cse-specific function (GP_EXT_GUID_SECURITY) retrieves the data
 * referenced by the input smb_uri, and uses the parsed results to populate the
 * state's list of allowed_sids and denied_sids.
 */
struct tevent_req *
ad_gpo_process_cse_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        char *smb_uri)
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

    state->ev = ev;
    state->buf = NULL;
    state->len = 0;

    state->io = talloc(state, struct io);
    if (state->io == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    state->io->write_to_child_fd = -1;
    state->io->read_from_child_fd = -1;
    talloc_set_destructor((void *) state->io, gpo_child_io_destructor);

    /* prepare the data to pass to child */
    ret = create_cse_send_buffer(state, smb_uri, &buf);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "create_cse_send_buffer failed.\n");
        goto fail;
    }

    ret = gpo_fork_child(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "gpo_fork_child failed.\n");
        goto fail;
    }

    subreq = write_pipe_send(state, ev, buf->data, buf->size,
                             state->io->write_to_child_fd);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, gpo_cse_step, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
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

    close(state->io->write_to_child_fd);
    state->io->write_to_child_fd = -1;

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

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_process_cse_state);
    int ret;

    ret = read_pipe_recv(subreq, state, &state->buf, &state->len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    close(state->io->read_from_child_fd);
    state->io->read_from_child_fd = -1;

    tevent_req_done(req);
    return;
}

int ad_gpo_process_cse_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            int *_allowed_size,
                            char ***_allowed_sids,
                            int *_denied_size,
                            char ***_denied_sids)
{
    int ret;
    char **allowed_sids;
    int allowed_size;
    char **denied_sids;
    int denied_size;
    struct ad_gpo_process_cse_state *state;

    state = tevent_req_data(req, struct ad_gpo_process_cse_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    ret = parse_gpo_child_response(mem_ctx, state->buf, state->len,
                                   &allowed_sids,
                                   &allowed_size,
                                   &denied_sids,
                                   &denied_size);

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot parse child response: [%d][%s]\n", ret, strerror(ret));
        return ret;
    }

    *_allowed_size = allowed_size;
    *_allowed_sids = talloc_steal(mem_ctx, allowed_sids);
    *_denied_size = denied_size;
    *_denied_sids = talloc_steal(mem_ctx, denied_sids);

    return EOK;
}

static errno_t
gpo_fork_child(struct tevent_req *req)
{
    int pipefd_to_child[2];
    int pipefd_from_child[2];
    pid_t pid;
    int ret;
    errno_t err;
    struct ad_gpo_process_cse_state *state;

    state = tevent_req_data(req, struct ad_gpo_process_cse_state);

    ret = pipe(pipefd_from_child);
    if (ret == -1) {
        err = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe failed [%d][%s].\n", errno, strerror(errno));
        return err;
    }
    ret = pipe(pipefd_to_child);
    if (ret == -1) {
        err = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe failed [%d][%s].\n", errno, strerror(errno));
        return err;
    }

    pid = fork();

    if (pid == 0) { /* child */
        err = exec_child(state,
                         pipefd_to_child, pipefd_from_child,
                         GPO_CHILD, gpo_child_debug_fd);
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not exec gpo_child: [%d][%s].\n",
              err, strerror(err));
        return err;
    } else if (pid > 0) { /* parent */
        state->child_pid = pid;
        state->io->read_from_child_fd = pipefd_from_child[0];
        close(pipefd_from_child[1]);
        state->io->write_to_child_fd = pipefd_to_child[1];
        close(pipefd_to_child[0]);
        fd_nonblocking(state->io->read_from_child_fd);
        fd_nonblocking(state->io->write_to_child_fd);

        ret = child_handler_setup(state->ev, pid, NULL, NULL, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Could not set up child signal handler\n");
            return ret;
        }
    } else { /* error */
        err = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "fork failed [%d][%s].\n", errno, strerror(errno));
        return err;
    }

    return EOK;
}
