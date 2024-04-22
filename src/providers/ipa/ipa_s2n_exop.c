/*
    SSSD

    IPA Helper routines - external users and groups with s2n plugin

    Copyright (C) Sumit Bose <sbose@redhat.com> - 2011

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

#include "util/util.h"
#include "util/sss_nss.h"
#include "util/strtonum.h"
#include "util/crypto/sss_crypto.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/sdap_async_ad.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_idmap.h"
#include "providers/ipa/ipa_id.h"
#include "providers/ipa/ipa_subdomains.h"
#include "providers/ad/ad_pac.h"
#include "db/sysdb.h"

enum input_types {
    INP_SID = 1,
    INP_NAME,
    INP_POSIX_UID,
    INP_POSIX_GID,
    INP_CERT,
    INP_USERNAME,
    INP_GROUPNAME
};

enum request_types {
    REQ_SIMPLE = 1,
    REQ_FULL,
    REQ_FULL_WITH_MEMBERS
};

enum response_types {
    RESP_SID = 1,
    RESP_NAME,
    RESP_USER,
    RESP_GROUP,
    RESP_USER_GROUPLIST,
    RESP_GROUP_MEMBERS,
    RESP_NAME_LIST
};

struct extdom_protocol_map_item {
    int protocol;
    const char *oid;
};

static struct extdom_protocol_map_item extdom_protocol_map[] = {
    { EXTDOM_V2, EXOP_SID2NAME_V2_OID },
    { EXTDOM_V1, EXOP_SID2NAME_V1_OID },
    { EXTDOM_V0, EXOP_SID2NAME_OID },
    { EXTDOM_INVALID_VERSION, NULL }
};

static const char* extdom_protocol_to_oid(enum extdom_protocol protocol)
{
    int i;

    for (i = 0; extdom_protocol_map[i].protocol != EXTDOM_INVALID_VERSION; ++i) {
        if (extdom_protocol_map[i].protocol == protocol) {
            return extdom_protocol_map[i].oid;
        }
    }

    return NULL;
}

static enum extdom_protocol extdom_oid_to_protocol(const char *oid)
{
    int i;

    if (oid == NULL) {
        return EXTDOM_INVALID_VERSION;
    }

    for (i = 0; extdom_protocol_map[i].protocol != EXTDOM_INVALID_VERSION; ++i) {
        if (strcmp(extdom_protocol_map[i].oid, oid) == 0) {
            return extdom_protocol_map[i].protocol;
        }
    }

    return EXTDOM_INVALID_VERSION;
}

static enum extdom_protocol extdom_preferred_protocol(struct sdap_handle *sh) {
    if (sdap_is_extension_supported(sh, EXOP_SID2NAME_V2_OID)) {
        return EXTDOM_V2;
    }

    if (sdap_is_extension_supported(sh, EXOP_SID2NAME_V1_OID)) {
        return EXTDOM_V1;
    }

    if (sdap_is_extension_supported(sh, EXOP_SID2NAME_OID)) {
        return EXTDOM_V0;
    }

    return EXTDOM_INVALID_VERSION;
}

static const char *ipa_s2n_reqtype2str(enum request_types request_type)
{
    switch (request_type) {
    case REQ_SIMPLE:
        return "REQ_SIMPLE";
    case REQ_FULL:
        return "REQ_FULL";
    case REQ_FULL_WITH_MEMBERS:
        return "REQ_FULL_WITH_MEMBERS";
    default:
        break;
    }

    return "Unknown request type";
}

/* ==Sid2Name Extended Operation============================================= */
struct ipa_s2n_exop_state {
    struct sdap_handle *sh;

    struct sdap_op *op;

    char *retoid;
    struct berval *retdata;
};

static void ipa_s2n_exop_done(struct sdap_op *op,
                           struct sdap_msg *reply,
                           int error, void *pvt);

static struct tevent_req *ipa_s2n_exop_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct sdap_handle *sh,
                                            enum extdom_protocol protocol,
                                            int timeout,
                                            struct berval *bv,
                                            const char *stat_info_in)
{
    struct tevent_req *req = NULL;
    struct ipa_s2n_exop_state *state;
    int ret;
    int msgid;
    char *stat_info;

    req = tevent_req_create(mem_ctx, &state, struct ipa_s2n_exop_state);
    if (!req) return NULL;

    state->sh = sh;
    state->retoid = NULL;
    state->retdata = NULL;

    DEBUG(SSSDBG_TRACE_FUNC, "Executing extended operation\n");

    ret = ldap_extended_operation(state->sh->ldap,
                                  extdom_protocol_to_oid(protocol),
                                  bv, NULL, NULL, &msgid);
    if (ret == -1 || msgid == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ldap_extended_operation failed\n");
        ret = ERR_NETWORK_IO;
        goto fail;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "ldap_extended_operation sent, msgid = %d\n",
                                  msgid);

    stat_info = talloc_asprintf(state, "server: [%s] %s",
                                sdap_get_server_peer_str_safe(state->sh),
                                stat_info_in != NULL ? stat_info_in
                                                     : "IPA EXOP");
    if (stat_info == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create info string, ignored.\n");
    }

    ret = sdap_op_add(state, ev, state->sh, msgid, stat_info,
                      ipa_s2n_exop_done, req, timeout, &state->op);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set up operation!\n");
        ret = ERR_INTERNAL;
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ipa_s2n_exop_done(struct sdap_op *op,
                               struct sdap_msg *reply,
                               int error, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct ipa_s2n_exop_state *state = tevent_req_data(req,
                                                    struct ipa_s2n_exop_state);
    int ret;
    char *errmsg = NULL;
    char *retoid = NULL;
    struct berval *retdata = NULL;
    int result;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    ret = ldap_parse_result(state->sh->ldap, reply->msg,
                            &result, NULL, &errmsg, NULL,
                            NULL, 0);
    if (ret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldap_parse_result failed (%d)\n",
                                 sdap_op_get_msgid(state->op));
        ret = ERR_NETWORK_IO;
        goto done;
    }

    DEBUG(((result == LDAP_SUCCESS) || (result == LDAP_NO_SUCH_OBJECT)) ?
              SSSDBG_TRACE_FUNC : SSSDBG_OP_FAILURE,
          "ldap_extended_operation result: %s(%d), %s.\n",
          sss_ldap_err2string(result), result, errmsg);

    if (result != LDAP_SUCCESS) {
        if (result == LDAP_NO_SUCH_OBJECT) {
            ret = ENOENT;
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "ldap_extended_operation failed, server " \
                                     "logs might contain more details.\n");
            ret = ERR_NETWORK_IO;
        }
        goto done;
    }

    ret = ldap_parse_extended_result(state->sh->ldap, reply->msg,
                                      &retoid, &retdata, 0);
    if (ret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "ldap_parse_extendend_result failed (%d)\n",
                                 ret);
        ret = ERR_NETWORK_IO;
        goto done;
    }
    if (retdata == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing exop result data.\n");
        ret = EINVAL;
        goto done;
    }

    state->retoid = talloc_strdup(state, retoid);
    if (state->retoid == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    state->retdata = talloc(state, struct berval);
    if (state->retdata == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc failed.\n");
        ret = ENOMEM;
        goto done;
    }
    state->retdata->bv_len = retdata->bv_len;
    state->retdata->bv_val = talloc_memdup(state->retdata, retdata->bv_val,
                                           retdata->bv_len);
    if (state->retdata->bv_val == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_memdup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    ldap_memfree(errmsg);
    ldap_memfree(retoid);
    ber_bvfree(retdata);
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static int ipa_s2n_exop_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                             char **retoid, struct berval **retdata)
{
    struct ipa_s2n_exop_state *state = tevent_req_data(req,
                                                    struct ipa_s2n_exop_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *retoid = talloc_steal(mem_ctx, state->retoid);
    *retdata = talloc_steal(mem_ctx, state->retdata);

    return EOK;
}

static errno_t talloc_ber_flatten(TALLOC_CTX *mem_ctx, BerElement *ber,
                                  struct berval **_bv)
{
    int ret;
    struct berval *bv = NULL;
    struct berval *tbv = NULL;

    ret = ber_flatten(ber, &bv);
    if (ret == -1) {
        ret = EFAULT;
        goto done;
    }

    tbv = talloc_zero(mem_ctx, struct berval);
    if (tbv == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tbv->bv_len = bv->bv_len;
    tbv->bv_val = talloc_memdup(tbv, bv->bv_val, bv->bv_len);
    if (tbv->bv_val == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    ber_bvfree(bv);
    if (ret == EOK) {
        *_bv = tbv;
    } else  {
        talloc_free(tbv);
    }

    return ret;
}

/* The extended operation expect the following ASN.1 encoded request data:
 *
 * ExtdomRequestValue ::= SEQUENCE {
 *    inputType ENUMERATED {
 *        sid (1),
 *        name (2),
 *        posix uid (3),
 *        posix gid (3)
 *    },
 *    requestType ENUMERATED {
 *        simple (1),
 *        full (2)
 *        full_with_members (3)
 *    },
 *    data InputData
 * }
 *
 * InputData ::= CHOICE {
 *    sid OCTET STRING,
 *    name NameDomainData
 *    uid PosixUid,
 *    gid PosixGid
 * }
 *
 * NameDomainData ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    object_name OCTET STRING
 * }
 *
 * PosixUid ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    uid INTEGER
 * }
 *
 * PosixGid ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    gid INTEGER
 * }
 *
 */

static errno_t s2n_encode_request(TALLOC_CTX *mem_ctx,
                                  const char *domain_name,
                                  int entry_type,
                                  enum request_types request_type,
                                  struct req_input *req_input,
                                  enum extdom_protocol protocol,
                                  struct berval **_bv,
                                  char **stat_info)
{
    BerElement *ber = NULL;
    int ret;
    char *info = NULL;

    if (protocol == EXTDOM_INVALID_VERSION) {
        return EINVAL;
    }

    ber = ber_alloc_t( LBER_USE_DER );
    if (ber == NULL) {
        return ENOMEM;
    }

    switch (entry_type) {
        case BE_REQ_USER:
        case BE_REQ_USER_AND_GROUP:  /* the extdom V0/V1 exop does not care if
                                        the ID belongs to a user or a group */
            if (req_input->type == REQ_INP_NAME) {
                ret = ber_printf(ber, "{ee{ss}}",
                                 (protocol == EXTDOM_V2
                                  ? INP_USERNAME : INP_NAME),
                                 request_type,
                                 domain_name,
                                 req_input->inp.name);
                info = talloc_asprintf(mem_ctx,
                            "EXTDOM EXPO request: [%s] domain: [%s] name: [%s]",
                            ipa_s2n_reqtype2str(request_type),
                            domain_name, req_input->inp.name);
            } else if (req_input->type == REQ_INP_ID) {
                ret = ber_printf(ber, "{ee{si}}", INP_POSIX_UID, request_type,
                                                  domain_name,
                                                  req_input->inp.id);
                info = talloc_asprintf(mem_ctx,
                            "EXTDOM EXPO request: [%s] domain: [%s] id: [%" PRIu32 "]",
                            ipa_s2n_reqtype2str(request_type),
                            domain_name, req_input->inp.id);
            } else {
                DEBUG(SSSDBG_OP_FAILURE, "Unexpected input type [%d].\n",
                                          req_input->type);
                ret = EINVAL;
                goto done;
            }
            break;
        case BE_REQ_GROUP:
            if (req_input->type == REQ_INP_NAME) {
                ret = ber_printf(ber, "{ee{ss}}",
                                 (protocol == EXTDOM_V2
                                  ? INP_GROUPNAME : INP_NAME),
                                 request_type,
                                 domain_name,
                                 req_input->inp.name);
                info = talloc_asprintf(mem_ctx,
                            "EXTDOM EXPO request: [%s] domain: [%s] name: [%s]",
                            ipa_s2n_reqtype2str(request_type),
                            domain_name, req_input->inp.name);
            } else if (req_input->type == REQ_INP_ID) {
                ret = ber_printf(ber, "{ee{si}}", INP_POSIX_GID, request_type,
                                                  domain_name,
                                                  req_input->inp.id);
                info = talloc_asprintf(mem_ctx,
                            "EXTDOM EXPO request: [%s] domain: [%s] id: [%" PRIu32 "]",
                            ipa_s2n_reqtype2str(request_type),
                            domain_name, req_input->inp.id);
            } else {
                DEBUG(SSSDBG_OP_FAILURE, "Unexpected input type [%d].\n",
                                          req_input->type);
                ret = EINVAL;
                goto done;
            }
            break;
        case BE_REQ_BY_SECID:
            if (req_input->type == REQ_INP_SECID) {
                ret = ber_printf(ber, "{ees}", INP_SID, request_type,
                                               req_input->inp.secid);
                info = talloc_asprintf(mem_ctx,
                            "EXTDOM EXPO request: [%s] sid: [%s]",
                            ipa_s2n_reqtype2str(request_type),
                            req_input->inp.secid);
            } else {
                DEBUG(SSSDBG_OP_FAILURE, "Unexpected input type [%d].\n",
                                         req_input->type);
                ret = EINVAL;
                goto done;
            }
            break;
        case BE_REQ_BY_CERT:
            if (req_input->type == REQ_INP_CERT) {
                ret = ber_printf(ber, "{ees}", INP_CERT, request_type,
                                               req_input->inp.cert);
                info = talloc_asprintf(mem_ctx,
                            "EXTDOM EXPO request: [%s] cert: [%s]",
                            ipa_s2n_reqtype2str(request_type),
                            req_input->inp.cert);
            } else {
                DEBUG(SSSDBG_OP_FAILURE, "Unexpected input type [%d].\n",
                                          req_input->type);
                ret = EINVAL;
                goto done;
            }
            break;
        default:
            ret = EINVAL;
            goto done;
    }
    if (ret == -1) {
        ret = EFAULT;
        goto done;
    }

    ret = talloc_ber_flatten(mem_ctx, ber, _bv);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    ber_free(ber, 1);
    if (ret != EOK || (*stat_info == NULL)) {
        talloc_free(info);
    } else {
        *stat_info = info;
    }

    return ret;
}

/* If the extendend operation is successful it returns the following ASN.1
 * encoded response:
 *
 * ExtdomResponseValue ::= SEQUENCE {
 *    responseType ENUMERATED {
 *        sid (1),
 *        name (2),
 *        posix_user (3),
 *        posix_group (4),
 *        posix_user_grouplist (5),
 *        posix_group_members (6)
 *    },
 *    data OutputData
 * }
 *
 * OutputData ::= CHOICE {
 *    sid OCTET STRING,
 *    name NameDomainData,
 *    user PosixUser,
 *    group PosixGroup,
 *    usergrouplist PosixUserGrouplist,
 *    groupmembers PosixGroupMembers
 *
 * }
 *
 * NameDomainData ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    object_name OCTET STRING
 * }
 *
 * PosixUser ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    user_name OCTET STRING,
 *    uid INTEGER
 *    gid INTEGER
 * }
 *
 * PosixGroup ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    group_name OCTET STRING,
 *    gid INTEGER
 * }
 *
 * PosixUserGrouplist ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    user_name OCTET STRING,
 *    uid INTEGER,
 *    gid INTEGER,
 *    gecos OCTET STRING,
 *    home_directory OCTET STRING,
 *    shell OCTET STRING,
 *    grouplist GroupNameList
 * }
 *
 * GroupNameList ::= SEQUENCE OF OCTET STRING
 *
 * PosixGroupMembers ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    group_name OCTET STRING,
 *    gid INTEGER,
 *    members GroupMemberList
 * }
 *
 * GroupMemberList ::= SEQUENCE OF OCTET STRING
 */

struct name_list {
    char *domain_name;
    char *name;
};

struct resp_attrs {
    enum response_types response_type;
    char *domain_name;
    union {
        struct passwd user;
        struct group group;
        char *sid_str;
        char *name;
    } a;
    size_t ngroups;
    char **groups;
    struct sysdb_attrs *sysdb_attrs;
    char **name_list;
};

static errno_t get_extra_attrs(BerElement *ber, struct resp_attrs *resp_attrs)
{
    ber_tag_t tag;
    ber_len_t ber_len;
    char *ber_cookie;
    char *name;
    struct berval **values;
    struct ldb_val v;
    int ret;
    size_t c;

    if (resp_attrs->sysdb_attrs == NULL) {
        resp_attrs->sysdb_attrs = sysdb_new_attrs(resp_attrs);
        if (resp_attrs->sysdb_attrs == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs failed.\n");
            return ENOMEM;
        }
    }

    DEBUG(SSSDBG_TRACE_ALL, "Found new sequence.\n");
    for (tag = ber_first_element(ber, &ber_len, &ber_cookie);
         tag != LBER_DEFAULT;
         tag = ber_next_element(ber, &ber_len, ber_cookie)) {

        tag = ber_scanf(ber, "{a{V}}", &name, &values);
        if (tag == LBER_ERROR) {
            DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
            return EINVAL;
        }
        DEBUG(SSSDBG_TRACE_ALL, "Extra attribute [%s].\n", name);

        for (c = 0; values[c] != NULL; c++) {

            if (strcmp(name, SYSDB_USER_CERT) == 0) {
                if (values[c]->bv_val[values[c]->bv_len] != '\0') {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "base64 encoded certificate not 0-terminated.\n");
                    return EINVAL;
                }

                v.data = sss_base64_decode(NULL, values[c]->bv_val, &v.length);
                if (v.data == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "sss_base64_decode failed.\n");
                    return EINVAL;
                }
            } else {
                v.data = (uint8_t *)values[c]->bv_val;
                v.length = values[c]->bv_len;
            }

            ret = sysdb_attrs_add_val_safe(resp_attrs->sysdb_attrs, name, &v);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_val_safe failed.\n");
                ldap_memfree(name);
                ber_bvecfree(values);
                return ret;
            }
        }

        ldap_memfree(name);
        ber_bvecfree(values);
    }

    return EOK;
}

static errno_t add_v1_user_data(struct sss_domain_info *dom,
                                BerElement *ber,
                                struct resp_attrs *attrs)
{
    ber_tag_t tag;
    ber_len_t ber_len;
    int ret;
    char *gecos = NULL;
    char *homedir = NULL;
    char *name = NULL;
    char *domain = NULL;
    char *shell = NULL;
    char **list = NULL;
    size_t c, gc;
    struct sss_domain_info *parent_domain;
    struct sss_domain_info *obj_domain;

    tag = ber_scanf(ber, "aaa", &gecos, &homedir, &shell);
    if (tag == LBER_ERROR) {
        DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
        ret = EINVAL;
        goto done;
    }

    if (gecos == NULL || *gecos == '\0') {
        attrs->a.user.pw_gecos = NULL;
    } else {
        attrs->a.user.pw_gecos = talloc_strdup(attrs, gecos);
        if (attrs->a.user.pw_gecos == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    if (homedir == NULL || *homedir == '\0') {
        attrs->a.user.pw_dir = NULL;
    } else {
        attrs->a.user.pw_dir = talloc_strdup(attrs, homedir);
        if (attrs->a.user.pw_dir == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    if (shell == NULL || *shell == '\0') {
        attrs->a.user.pw_shell = NULL;
    } else {
        attrs->a.user.pw_shell = talloc_strdup(attrs, shell);
        if (attrs->a.user.pw_shell == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    tag = ber_scanf(ber, "{v}", &list);
    if (tag == LBER_ERROR) {
        DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
        ret = EINVAL;
        goto done;
    }

    for (attrs->ngroups = 0; list[attrs->ngroups] != NULL;
         attrs->ngroups++);

    if (attrs->ngroups > 0) {
        attrs->groups = talloc_zero_array(attrs, char *, attrs->ngroups + 1);
        if (attrs->groups == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array failed.\n");
            attrs->ngroups = 0;
            ret = ENOMEM;
            goto done;
        }

        parent_domain = get_domains_head(dom);

        for (c = 0, gc = 0; c < attrs->ngroups; c++) {
            ret = sss_parse_name(attrs, dom->names, list[c],
                                 &domain, &name);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                        "Cannot parse member %s\n", list[c]);
                continue;
            }

            if (domain != NULL) {
                obj_domain = find_domain_by_name_ex(parent_domain, domain, true, SSS_GND_ALL_DOMAINS);
                if (obj_domain == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "find_domain_by_name_ex failed.\n");
                    attrs->ngroups = gc;
                    ret = ENOMEM;
                    goto done;
                } else if (sss_domain_get_state(obj_domain) == DOM_DISABLED) {
                    /* skipping objects from disabled domains */
                    DEBUG(SSSDBG_TRACE_ALL,
                          "Skipping object [%s] from disabled domain.\n",
                          list[c]);
                    continue;
                }
            } else {
                obj_domain = parent_domain;
            }

            attrs->groups[gc] = sss_create_internal_fqname(attrs->groups,
                                                           name, obj_domain->name);
            if (attrs->groups[gc] == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "sss_create_internal_fqname failed.\n");
                attrs->ngroups = gc;
                ret = ENOMEM;
                goto done;
            }
            gc++;
        }
        attrs->ngroups = gc;
    }

    tag = ber_peek_tag(ber, &ber_len);
    DEBUG(SSSDBG_TRACE_ALL, "BER tag is [%d]\n", (int) tag);
    if (tag == LBER_SEQUENCE) {
        ret = get_extra_attrs(ber, attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "get_extra_attrs failed.\n");
            goto done;
        }
    }


    ret = EOK;

done:
    ber_memfree(gecos);
    ber_memfree(homedir);
    ber_memfree(shell);
    ber_memvfree((void **) list);

    return ret;
}

static errno_t add_v1_group_data(BerElement *ber,
                                 struct sss_domain_info *dom,
                                 struct resp_attrs *attrs)
{
    ber_tag_t tag;
    ber_len_t ber_len;
    int ret;
    char **list = NULL;
    size_t c, mc;
    char *name = NULL;
    char *domain = NULL;

    tag = ber_scanf(ber, "{v}", &list);
    if (tag == LBER_ERROR) {
        DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
        ret = EINVAL;
        goto done;
    }

    if (list != NULL) {
        for (attrs->ngroups = 0; list[attrs->ngroups] != NULL;
             attrs->ngroups++);

        if (attrs->ngroups > 0) {
            attrs->a.group.gr_mem = talloc_zero_array(attrs, char *,
                                                    attrs->ngroups + 1);
            if (attrs->a.group.gr_mem == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
                ret = ENOMEM;
                goto done;
            }

            for (c = 0, mc=0; c < attrs->ngroups; c++) {
                ret = sss_parse_name(attrs, dom->names, list[c],
                                     &domain, &name);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "Cannot parse member %s\n", list[c]);
                    continue;
                }

                if (domain == NULL) {
                    domain = dom->name;
                }

                attrs->a.group.gr_mem[mc] =
                            sss_create_internal_fqname(attrs->a.group.gr_mem,
                                                       name, domain);
                if (attrs->a.group.gr_mem[mc] == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                    ret = ENOMEM;
                    goto done;
                }
                mc++;
            }
        }
    } else {
        attrs->a.group.gr_mem = talloc_zero_array(attrs, char *, 1);
        if (attrs->a.group.gr_mem == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    tag = ber_peek_tag(ber, &ber_len);
    DEBUG(SSSDBG_TRACE_ALL, "BER tag is [%d]\n", (int) tag);
    if (tag == LBER_SEQUENCE) {
        ret = get_extra_attrs(ber, attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "get_extra_attrs failed.\n");
            goto done;
        }
    }

    ret = EOK;

done:
    ber_memvfree((void **) list);

    return ret;
}

static char *s2n_response_to_attrs_fqname(TALLOC_CTX *mem_ctx,
                                          enum extdom_protocol protocol,
                                          const char *domain_name,
                                          const char *name)
{
    char *lc_name;
    char *out_name;

    if (protocol == EXTDOM_V0) {
        /* Compatibility with older IPA servers that may use winbind instead
         * of SSSD's server mode.
         *
         * Winbind is not consistent with the case of the returned user
         * name. In general all names should be lower case but there are
         * bug in some version of winbind which might lead to upper case
         * letters in the name. To be on the safe side we explicitly
         * lowercase the name.
         */

        lc_name = sss_tc_utf8_str_tolower(NULL, name);
        if (lc_name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
            return NULL;
        }

        out_name = sss_create_internal_fqname(mem_ctx, lc_name, domain_name);
        talloc_free(lc_name);
    } else {
        /* Keep the original casing to support case_sensitive=Preserving */
        out_name = sss_create_internal_fqname(mem_ctx, name, domain_name);
    }

    if (out_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
        return NULL;
    }

    return out_name;
}

static errno_t ipa_s2n_save_objects(struct sss_domain_info *dom,
                                    struct req_input *req_input,
                                    struct resp_attrs *attrs,
                                    struct resp_attrs *simple_attrs,
                                    const char *view_name,
                                    struct sysdb_attrs *override_attrs,
                                    struct sysdb_attrs *mapped_attrs,
                                    bool update_initgr_timeout);

static errno_t s2n_response_to_attrs(TALLOC_CTX *mem_ctx,
                                     struct sss_domain_info *dom,
                                     char *retoid,
                                     struct berval *retdata,
                                     struct resp_attrs **resp_attrs)
{
    BerElement *ber = NULL;
    ber_tag_t tag;
    int ret;
    enum response_types type;
    char *domain_name = NULL;
    char *name = NULL;
    uid_t uid;
    gid_t gid;
    struct resp_attrs *attrs = NULL;
    char *sid_str;
    enum extdom_protocol protocol;
    char **name_list = NULL;
    ber_len_t ber_len;
    char *fq_name = NULL;
    struct sss_domain_info *root_domain = NULL;

    if (retoid == NULL || retdata == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing OID or data.\n");
        return EINVAL;
    }

    protocol = extdom_oid_to_protocol(retoid);
    if (protocol == EXTDOM_INVALID_VERSION) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Result has wrong OID, expected [%s], [%s] or [%s], got [%s].\n",
              EXOP_SID2NAME_OID, EXOP_SID2NAME_V1_OID,
              EXOP_SID2NAME_V2_OID, retoid);
        return EINVAL;
    }

    ber = ber_init(retdata);
    if (ber == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ber_init failed.\n");
        return EINVAL;
    }

    tag = ber_scanf(ber, "{e", &type);
    if (tag == LBER_ERROR) {
        DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
        ret = EINVAL;
        goto done;
    }

    attrs = talloc_zero(mem_ctx, struct resp_attrs);
    if (attrs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    switch (type) {
        case RESP_USER:
        case RESP_USER_GROUPLIST:
            tag = ber_scanf(ber, "{aaii", &domain_name, &name, &uid, &gid);
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
                ret = EINVAL;
                goto done;
            }

            attrs->a.user.pw_name = s2n_response_to_attrs_fqname(attrs,
                                                                 protocol,
                                                                 domain_name,
                                                                 name);
            if (attrs->a.user.pw_name == NULL) {
                ret = ENOMEM;
                goto done;
            }

            attrs->a.user.pw_uid = uid;
            attrs->a.user.pw_gid = gid;

            if (protocol > EXTDOM_V0 && type == RESP_USER_GROUPLIST) {
                ret = add_v1_user_data(dom, ber, attrs);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "add_v1_user_data failed.\n");
                    goto done;
                }
            }

            tag = ber_scanf(ber, "}}");
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
                ret = EINVAL;
                goto done;
            }

            break;
        case RESP_GROUP:
        case RESP_GROUP_MEMBERS:
            tag = ber_scanf(ber, "{aai", &domain_name, &name, &gid);
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
                ret = EINVAL;
                goto done;
            }

            attrs->a.group.gr_name = s2n_response_to_attrs_fqname(attrs,
                                                                  protocol,
                                                                  domain_name,
                                                                  name);
            if (attrs->a.group.gr_name == NULL) {
                ret = ENOMEM;
                goto done;
            }

            attrs->a.group.gr_gid = gid;

            if (protocol > EXTDOM_V0 && type == RESP_GROUP_MEMBERS) {
                ret = add_v1_group_data(ber, dom, attrs);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "add_v1_group_data failed.\n");
                    goto done;
                }
            }

            tag = ber_scanf(ber, "}}");
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
                ret = EINVAL;
                goto done;
            }

            break;
        case RESP_SID:
            tag = ber_scanf(ber, "a}", &sid_str);
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
                ret = EINVAL;
                goto done;
            }

            attrs->a.sid_str = talloc_strdup(attrs, sid_str);
            if (attrs->a.sid_str == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
            break;
        case RESP_NAME:
            tag = ber_scanf(ber, "{aa}", &domain_name, &name);
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
                ret = EINVAL;
                goto done;
            }

            attrs->a.name = sss_tc_utf8_str_tolower(attrs, name);
            if (attrs->a.name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "sss_tc_utf8_str_tolower failed.\n");
                ret = ENOMEM;
                goto done;
            }
            break;
        case RESP_NAME_LIST:
            tag = ber_scanf(ber, "{");
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
                ret = EINVAL;
                goto done;
            }

            root_domain = get_domains_head(dom);

            while (ber_peek_tag(ber, &ber_len) ==  LBER_SEQUENCE) {
                tag = ber_scanf(ber, "{aa}", &domain_name, &name);
                if (tag == LBER_ERROR) {
                    DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
                    ret = EINVAL;
                    goto done;
                }

                fq_name = sss_create_internal_fqname(attrs, name, domain_name);
                if (fq_name == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sss_create_internal_fqname failed.\n");
                    ret = ENOMEM;
                    goto done;
                }
                DEBUG(SSSDBG_TRACE_ALL, "[%s][%s][%s].\n", domain_name, name,
                                                           fq_name);

                if (strcasecmp(root_domain->name, domain_name) != 0) {
                    ret = add_string_to_list(attrs, fq_name, &name_list);
                } else {
                    DEBUG(SSSDBG_TRACE_ALL,
                          "[%s] from root domain, skipping.\n", fq_name);
                    ret = EOK; /* Free resources and continue in the loop */
                }
                ber_memfree(domain_name);
                ber_memfree(name);
                talloc_free(fq_name);
                domain_name = NULL;
                name = NULL;
                fq_name = NULL;
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "add_to_name_list failed.\n");
                    goto done;
                }
            }

            tag = ber_scanf(ber, "}}");
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, "ber_scanf failed.\n");
                ret = EINVAL;
                goto done;
            }
            attrs->name_list = name_list;
            break;
        default:
            DEBUG(SSSDBG_OP_FAILURE, "Unexpected response type [%d].\n",
                                      type);
            ret = EINVAL;
            goto done;
    }

    attrs->response_type = type;
    if (type != RESP_SID && type != RESP_NAME_LIST) {
        attrs->domain_name = talloc_strdup(attrs, domain_name);
        if (attrs->domain_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    ret = EOK;

done:
    ber_memfree(domain_name);
    ber_memfree(name);
    talloc_free(fq_name);
    ber_free(ber, 1);

    if (ret == EOK) {
        *resp_attrs = attrs;
    } else {
        talloc_free(attrs);
    }

    return ret;
}

static const char *ipa_s2n_reqinp2str(TALLOC_CTX *mem_ctx,
                                      struct req_input *req_input)
{
    const char *str = NULL;

    switch (req_input->type) {
    case REQ_INP_NAME:
        str = talloc_strdup(mem_ctx, req_input->inp.name);
        break;
    case REQ_INP_SECID:
        str = talloc_strdup(mem_ctx, req_input->inp.secid);
        break;
    case REQ_INP_CERT:
        str = talloc_strdup(mem_ctx, req_input->inp.cert);
        break;
    case REQ_INP_ID:
        str = talloc_asprintf(mem_ctx, "%u", req_input->inp.id);
        break;
    }

    if (str == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory!\n");
    }

    return str;
}

struct ipa_s2n_get_list_state {
    struct tevent_context *ev;
    struct ipa_id_ctx *ipa_ctx;
    struct sss_domain_info *dom;
    struct sdap_handle *sh;
    enum extdom_protocol protocol;
    struct req_input req_input;
    char **list;
    size_t list_idx;
    int exop_timeout;
    int entry_type;
    enum request_types request_type;
    struct resp_attrs *attrs;
    struct sss_domain_info *obj_domain;
    struct sysdb_attrs *override_attrs;
    struct sysdb_attrs *mapped_attrs;
};

static errno_t ipa_s2n_get_list_step(struct tevent_req *req);
static void ipa_s2n_get_list_get_override_done(struct tevent_req *subreq);
static void ipa_s2n_get_list_next(struct tevent_req *subreq);
static void ipa_s2n_get_list_ipa_next(struct tevent_req *subreq);
static errno_t ipa_s2n_get_list_save_step(struct tevent_req *req);

static struct tevent_req *ipa_s2n_get_list_send(TALLOC_CTX *mem_ctx,
                                                struct tevent_context *ev,
                                                struct ipa_id_ctx *ipa_ctx,
                                                struct sss_domain_info *dom,
                                                struct sdap_handle *sh,
                                                int exop_timeout,
                                                int entry_type,
                                                enum request_types request_type,
                                                enum req_input_type list_type,
                                                char **list,
                                                struct sysdb_attrs *mapped_attrs)
{
    int ret;
    struct ipa_s2n_get_list_state *state;
    struct tevent_req *req;

    req = tevent_req_create(mem_ctx, &state, struct ipa_s2n_get_list_state);
    if (req == NULL) {
        return NULL;
    }

    if ((entry_type == BE_REQ_BY_SECID && list_type != REQ_INP_SECID)
           || (entry_type != BE_REQ_BY_SECID && list_type == REQ_INP_SECID)) {
        DEBUG(SSSDBG_OP_FAILURE, "Invalid parameter combination [%d][%d].\n",
                                 request_type, list_type);
        ret = EINVAL;
        goto done;
    }

    state->ev = ev;
    state->ipa_ctx = ipa_ctx;
    state->dom = dom;
    state->sh = sh;
    state->protocol = extdom_preferred_protocol(sh);
    state->list = list;
    state->list_idx = 0;
    state->req_input.type = list_type;
    state->req_input.inp.name = NULL;
    state->exop_timeout = exop_timeout;
    state->entry_type = entry_type;
    state->request_type = request_type;
    state->attrs = NULL;
    state->override_attrs = NULL;
    state->mapped_attrs = mapped_attrs;

    ret = ipa_s2n_get_list_step(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_get_list_step failed.\n");
        goto done;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static errno_t ipa_s2n_get_list_step(struct tevent_req *req)
{
    int ret;
    struct ipa_s2n_get_list_state *state = tevent_req_data(req,
                                               struct ipa_s2n_get_list_state);
    struct berval *bv_req;
    struct tevent_req *subreq;
    struct sss_domain_info *parent_domain;
    char *short_name = NULL;
    char *domain_name = NULL;
    uint32_t id;
    char *endptr;
    struct dp_id_data *ar;
    char *stat_info = NULL;

    parent_domain = get_domains_head(state->dom);
    switch (state->req_input.type) {
    case REQ_INP_NAME:

        ret = sss_parse_name(state, state->dom->names, state->list[state->list_idx],
                             &domain_name, &short_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse name '%s' [%d]: %s\n",
                                        state->list[state->list_idx],
                                        ret, sss_strerror(ret));
            return ret;
        }

        if (domain_name) {
            state->obj_domain = find_domain_by_name(parent_domain,
                                                    domain_name, true);
            if (state->obj_domain == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "find_domain_by_name failed.\n");
                return ENOMEM;
            }
        } else {
            state->obj_domain = parent_domain;
        }

        state->req_input.inp.name = short_name;

        if (strcmp(state->obj_domain->name,
            state->ipa_ctx->sdap_id_ctx->be->domain->name) == 0) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Looking up IPA object [%s] from LDAP.\n",
                  state->list[state->list_idx]);
            ret = get_dp_id_data_for_user_name(state,
                                               state->list[state->list_idx],
                                               state->obj_domain->name,
                                               &ar);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to create lookup date for IPA object [%s].\n",
                      state->list[state->list_idx]);
                return ret;
            }
            ar->entry_type = state->entry_type;

            subreq = ipa_id_get_account_info_send(state, state->ev,
                                                  state->ipa_ctx, ar);
            if (subreq == NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "ipa_id_get_account_info_send failed.\n");
                return ENOMEM;
            }
            tevent_req_set_callback(subreq, ipa_s2n_get_list_ipa_next, req);

            return EOK;
        }

        break;
    case REQ_INP_ID:
        id = strtouint32(state->list[state->list_idx], &endptr, 10);
        if (errno != 0 || *endptr != '\0'
                || (state->list[state->list_idx] == endptr)) {
            DEBUG(SSSDBG_OP_FAILURE, "strtouint32 failed.\n");
            return EINVAL;
        }
        state->req_input.inp.id = id;
        state->obj_domain = state->dom;

        break;
    case REQ_INP_SECID:
        state->req_input.inp.secid = state->list[state->list_idx];
        state->obj_domain = find_domain_by_sid(parent_domain,
                                               state->req_input.inp.secid);
        if (state->obj_domain == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "find_domain_by_sid failed for SID [%s].\n",
                  state->req_input.inp.secid);
            return EINVAL;
        }

        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unexpected input type [%d].\n",
                                 state->req_input.type);
        return EINVAL;
    }

    ret = s2n_encode_request(state, state->obj_domain->name, state->entry_type,
                             state->request_type, &state->req_input,
                             state->protocol, &bv_req, &stat_info);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "s2n_encode_request failed.\n");
        return ret;
    }

    if (state->request_type == REQ_FULL_WITH_MEMBERS && state->protocol == EXTDOM_V0) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_exop failed, protocol > V0 needed for this request.\n");
        return EINVAL;
    }

    if (state->req_input.type == REQ_INP_NAME
            && state->req_input.inp.name != NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Sending request_type: [%s] for object [%s].\n",
              ipa_s2n_reqtype2str(state->request_type),
              state->list[state->list_idx]);
    }

    subreq = ipa_s2n_exop_send(state, state->ev, state->sh, state->protocol,
                               state->exop_timeout, bv_req, stat_info);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_exop_send failed.\n");
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, ipa_s2n_get_list_next, req);

    return EOK;
}

static void ipa_s2n_get_list_next(struct tevent_req *subreq)
{
    int ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_s2n_get_list_state *state = tevent_req_data(req,
                                               struct ipa_s2n_get_list_state);
    char *retoid = NULL;
    struct berval *retdata = NULL;
    const char *sid_str;
    struct dp_id_data *ar;

    ret = ipa_s2n_exop_recv(subreq, state, &retoid, &retdata);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "s2n exop request failed.\n");
        goto fail;
    }

    talloc_zfree(state->attrs);
    ret = s2n_response_to_attrs(state, state->dom, retoid, retdata,
                                &state->attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "s2n_response_to_attrs failed.\n");
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Received [%s] attributes from IPA server.\n",
                             state->attrs->a.name);

    if (is_default_view(state->ipa_ctx->view_name)) {
        ret = ipa_s2n_get_list_save_step(req);
        if (ret == EOK) {
            tevent_req_done(req);
        } else if (ret != EAGAIN) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_get_list_save_step failed.\n");
            goto fail;
        }

        return;
    }

    ret = sysdb_attrs_get_string(state->attrs->sysdb_attrs, SYSDB_SID_STR,
                                 &sid_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Object [%s] has no SID, please check the "
              "ipaNTSecurityIdentifier attribute on the server-side",
              state->attrs->a.name);
        goto fail;
    }

    ret = get_dp_id_data_for_sid(state, sid_str, state->obj_domain->name, &ar);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "get_dp_id_data_for_sid failed.\n");
        goto fail;
    }

    subreq = ipa_get_trusted_override_send(state, state->ev,
                           state->ipa_ctx->sdap_id_ctx,
                           state->ipa_ctx->ipa_options,
                           dp_opt_get_string(state->ipa_ctx->ipa_options->basic,
                                             IPA_KRB5_REALM),
                           state->ipa_ctx->view_name,
                           ar);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_get_trusted_override_send failed.\n");
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, ipa_s2n_get_list_get_override_done, req);

    return;

fail:
    tevent_req_error(req,ret);
    return;
}

static void ipa_s2n_get_list_ipa_next(struct tevent_req *subreq)
{
    int ret;
    int dp_error;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_s2n_get_list_state *state = tevent_req_data(req,
                                               struct ipa_s2n_get_list_state);

    ret = ipa_id_get_account_info_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_id_get_account_info failed: %d %d\n", ret,
                                 dp_error);
        goto done;
    }

    state->list_idx++;
    if (state->list[state->list_idx] == NULL) {
        tevent_req_done(req);
        return;
    }

    ret = ipa_s2n_get_list_step(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_get_list_step failed.\n");
        goto done;
    }

    return;

done:
    tevent_req_error(req,ret);
    return;
}

static void ipa_s2n_get_list_get_override_done(struct tevent_req *subreq)
{
    int ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_s2n_get_list_state *state = tevent_req_data(req,
                                               struct ipa_s2n_get_list_state);

    ret = ipa_get_trusted_override_recv(subreq, NULL, state, &state->override_attrs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "IPA override lookup failed: %d\n", ret);
        goto fail;
    }

    ret = ipa_s2n_get_list_save_step(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_get_list_save_step failed.\n");
        goto fail;
    }

    return;

fail:
    tevent_req_error(req,ret);
    return;
}

static errno_t ipa_s2n_get_list_save_step(struct tevent_req *req)
{
    int ret;
    struct ipa_s2n_get_list_state *state = tevent_req_data(req,
                                               struct ipa_s2n_get_list_state);

    ret = ipa_s2n_save_objects(state->dom, &state->req_input, state->attrs,
                               NULL, state->ipa_ctx->view_name,
                               state->override_attrs, state->mapped_attrs,
                               false);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_save_objects failed.\n");
        return ret;
    }

    state->list_idx++;
    if (state->list[state->list_idx] == NULL) {
        return EOK;
    }

    ret = ipa_s2n_get_list_step(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_get_list_step failed.\n");
        return ret;
    }

    return EAGAIN;
}

static int ipa_s2n_get_list_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct ipa_s2n_get_user_state {
    struct tevent_context *ev;
    struct ipa_id_ctx *ipa_ctx;
    struct sdap_options *opts;
    struct sss_domain_info *dom;
    struct sdap_handle *sh;
    enum extdom_protocol protocol;
    struct req_input *req_input;
    int entry_type;
    enum request_types request_type;
    struct resp_attrs *attrs;
    struct resp_attrs *simple_attrs;
    struct sysdb_attrs *override_attrs;
    struct sysdb_attrs *mapped_attrs;
    int exop_timeout;
};

static void ipa_s2n_get_user_done(struct tevent_req *subreq);

struct tevent_req *ipa_s2n_get_acct_info_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct ipa_id_ctx *ipa_ctx,
                                             struct sdap_options *opts,
                                             struct sss_domain_info *dom,
                                             struct sysdb_attrs *override_attrs,
                                             struct sdap_handle *sh,
                                             int entry_type,
                                             struct req_input *req_input)
{
    struct ipa_s2n_get_user_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct berval *bv_req = NULL;
    const char *input;
    int ret = EFAULT;
    char *stat_info = NULL;

    req = tevent_req_create(mem_ctx, &state, struct ipa_s2n_get_user_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->ipa_ctx = ipa_ctx;
    state->opts = opts;
    state->dom = dom;
    state->sh = sh;
    state->protocol = extdom_preferred_protocol(sh);
    state->req_input = req_input;
    state->entry_type = entry_type;
    state->attrs = NULL;
    state->simple_attrs = NULL;
    state->exop_timeout = dp_opt_get_int(opts->basic, SDAP_SEARCH_TIMEOUT);
    state->override_attrs = override_attrs;

    if (state->protocol == EXTDOM_V1 || state->protocol == EXTDOM_V2) {
        state->request_type = REQ_FULL_WITH_MEMBERS;
    } else if (state->protocol == EXTDOM_V0) {
        state->request_type = REQ_FULL;
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Extdom not supported on the server, "
                              "cannot resolve objects from trusted domains.\n");
        ret = EIO;
        goto fail;
    }

    if (entry_type == BE_REQ_BY_CERT) {
        /* Only REQ_SIMPLE is supported for BE_REQ_BY_CERT */
        state->request_type = REQ_SIMPLE;
    }

    ret = s2n_encode_request(state, dom->name, entry_type, state->request_type,
                             req_input, state->protocol, &bv_req, &stat_info);
    if (ret != EOK) {
        goto fail;
    }

    input = ipa_s2n_reqinp2str(state, req_input);
    DEBUG(SSSDBG_TRACE_FUNC,
          "Sending request_type: [%s] for trust user [%s] to IPA server\n",
          ipa_s2n_reqtype2str(state->request_type),
          input);
    talloc_zfree(input);

    subreq = ipa_s2n_exop_send(state, state->ev, state->sh, state->protocol,
                               state->exop_timeout, bv_req, stat_info);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_exop_send failed.\n");
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, ipa_s2n_get_user_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static errno_t process_members(struct sss_domain_info *domain,
                               bool is_default_view,
                               struct sysdb_attrs *group_attrs,
                               char **members,
                               TALLOC_CTX *mem_ctx, char ***_missing_members)
{
    int ret;
    size_t c;
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    const char *dn_str;
    struct sss_domain_info *obj_domain;
    struct sss_domain_info *parent_domain;
    char **missing_members = NULL;
    size_t miss_count = 0;
    const char *attrs[] = {SYSDB_NAME, SYSDB_OVERRIDE_DN, NULL};

    if (members == NULL) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "No members\n");
        if (_missing_members != NULL) {
            *_missing_members = NULL;
        }
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    if (_missing_members != NULL && mem_ctx != NULL) {
        /* count members */
        for (c = 0; members[c] != NULL; c++);
        missing_members = talloc_zero_array(tmp_ctx, char *, c + 1);
        if (missing_members == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_array_zero failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    parent_domain = get_domains_head(domain);

    for (c = 0; members[c] != NULL; c++) {
        obj_domain = find_domain_by_object_name_ex(parent_domain, members[c],
                                                   false, SSS_GND_ALL_DOMAINS);
        if (obj_domain == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "find_domain_by_object_name failed.\n");
            ret = ENOMEM;
            goto done;
        } else if (sss_domain_get_state(obj_domain) == DOM_DISABLED) {
            /* skip members from disabled domains */
            continue;
        }

        ret = sysdb_search_user_by_name(tmp_ctx, obj_domain, members[c], attrs,
                                        &msg);
        if (ret == EOK || ret == ENOENT) {
            if (ret == ENOENT
                    || (!is_default_view
                        && ldb_msg_find_attr_as_string(msg, SYSDB_OVERRIDE_DN,
                                                       NULL) == NULL)) {
                /* only add ghost if the member is really missing */
                if (group_attrs != NULL && ret == ENOENT) {
                    DEBUG(SSSDBG_TRACE_ALL, "Adding ghost member [%s]\n",
                                            members[c]);

                    /* There were cases where the server returned the same user
                     * multiple times */
                    ret = sysdb_attrs_add_string_safe(group_attrs, SYSDB_GHOST,
                                                      members[c]);
                    if (ret != EOK) {
                        DEBUG(SSSDBG_OP_FAILURE,
                              "sysdb_attrs_add_string failed.\n");
                        goto done;
                    }
                }

                if (missing_members != NULL) {
                    missing_members[miss_count] = talloc_strdup(missing_members,
                                                                members[c]);
                    if (missing_members[miss_count] == NULL) {
                        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                        ret = ENOMEM;
                        goto done;
                    }
                    miss_count++;
                }
            } else {
                if (group_attrs != NULL) {
                    dn_str = ldb_dn_get_linearized(msg->dn);
                    if (dn_str == NULL) {
                        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_get_linearized failed.\n");
                        ret = EINVAL;
                        goto done;
                    }

                    DEBUG(SSSDBG_TRACE_ALL, "Adding member [%s][%s]\n",
                                            members[c], dn_str);

                    ret = sysdb_attrs_add_string_safe(group_attrs, SYSDB_MEMBER,
                                                      dn_str);
                    if (ret != EOK) {
                        DEBUG(SSSDBG_OP_FAILURE,
                              "sysdb_attrs_add_string_safe failed.\n");
                        goto done;
                    }
                }
            }
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_user_by_name failed.\n");
            goto done;
        }
    }

    if (_missing_members != NULL)  {
        if (miss_count == 0) {
            *_missing_members = NULL;
        } else {
            if (mem_ctx != NULL) {
                *_missing_members = talloc_steal(mem_ctx, missing_members);
            } else {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Missing memory context for missing members list.\n");
                ret = EINVAL;
                goto done;
            }
        }
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t get_group_dn_list(TALLOC_CTX *mem_ctx,
                                 bool is_default_view,
                                 struct sss_domain_info *dom,
                                 size_t ngroups, char **groups,
                                 struct ldb_dn ***_dn_list,
                                 char ***_missing_groups)
{
    int ret;
    size_t c;
    TALLOC_CTX *tmp_ctx;
    struct ldb_dn **dn_list = NULL;
    char **missing_groups = NULL;
    struct ldb_message *msg = NULL;
    size_t n_dns = 0;
    size_t n_missing = 0;
    struct sss_domain_info *obj_domain;
    struct sss_domain_info *parent_domain;
    const char *attrs[] = {SYSDB_NAME, SYSDB_OVERRIDE_DN, NULL};

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    dn_list = talloc_zero_array(tmp_ctx, struct ldb_dn *, ngroups + 1);
    missing_groups = talloc_zero_array(tmp_ctx, char *, ngroups + 1);
    if (dn_list == NULL || missing_groups == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    parent_domain = (dom->parent == NULL) ? dom : dom->parent;

    for (c = 0; c < ngroups; c++) {
        obj_domain = find_domain_by_object_name(parent_domain, groups[c]);
        if (obj_domain == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "find_domain_by_object_name failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_search_group_by_name(tmp_ctx, obj_domain, groups[c], attrs,
                                         &msg);
        if (ret == EOK || ret == ENOENT) {
            if (ret == ENOENT
                    || (!is_default_view
                        && ldb_msg_find_attr_as_string(msg, SYSDB_OVERRIDE_DN,
                                                       NULL) == NULL)) {
                missing_groups[n_missing] = talloc_strdup(missing_groups,
                                                          groups[c]);
                if (missing_groups[n_missing] == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                    ret = ENOMEM;
                    goto done;
                }
                n_missing++;

            } else {
                dn_list[n_dns] = ldb_dn_copy(dn_list, msg->dn);
                if (dn_list[n_dns] == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_copy failed.\n");
                    ret = ENOMEM;
                    goto done;
                }
                n_dns++;
            }
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_group_by_name failed.\n");
            goto done;
        }
    }

    if (n_missing != 0) {
        *_missing_groups = talloc_steal(mem_ctx, missing_groups);
    } else {
        *_missing_groups = NULL;
    }

    if (n_dns != 0) {
        *_dn_list = talloc_steal(mem_ctx, dn_list);
    } else {
        *dn_list = NULL;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t s2n_remove_missing_object(TALLOC_CTX *mem_ctx,
                                         struct sss_domain_info *domain,
                                         int entry_type,
                                         struct req_input *req_input)
{
    int ret;
    bool name_is_upn = false;
    char *id_str = NULL;
    char *fq_name = NULL;

    if (req_input->type == REQ_INP_ID) {
        id_str = talloc_asprintf(mem_ctx, "%"SPRIuid, req_input->inp.id);
        if (id_str == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    switch (entry_type) {
    case BE_REQ_USER_AND_GROUP:
    case BE_REQ_USER:
        if (req_input->type == REQ_INP_NAME) {
            name_is_upn = strchr(req_input->inp.name, '@') == NULL ? false
                                                                   : true;
            /* Expand to fully-qualified internal name */
            if (!name_is_upn) {
                fq_name = sss_create_internal_fqname(mem_ctx,
                                                     req_input->inp.name,
                                                     domain->name);
                if (fq_name == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sss_create_internal_fqname failed.\n");
                    ret = ENOMEM;
                    goto done;
                }
            }
            ret = users_get_handle_no_user(mem_ctx, domain, BE_FILTER_NAME,
                                           fq_name != NULL ? fq_name
                                                          : req_input->inp.name,
                                           name_is_upn);
        } else if (req_input->type == REQ_INP_ID) {
            ret = users_get_handle_no_user(mem_ctx, domain, BE_FILTER_IDNUM,
                                           id_str, false);
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "Unexpected input type [%d].\n",
                                      req_input->type);
            ret = EINVAL;
            goto done;
        }
        if (ret != EOK || entry_type == BE_REQ_USER) {
            break;
        }
        /* Fallthough if BE_REQ_USER_AND_GROUP */
        SSS_ATTRIBUTE_FALLTHROUGH;
    case BE_REQ_GROUP:
        if (req_input->type == REQ_INP_NAME) {
            /* Expand to fully-qualified internal name */
            fq_name = sss_create_internal_fqname(mem_ctx,
                                                 req_input->inp.name,
                                                 domain->name);
            if (fq_name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sss_create_internal_fqname failed.\n");
                ret = ENOMEM;
                goto done;
            }
            ret = groups_get_handle_no_group(mem_ctx, domain, BE_FILTER_NAME,
                                             fq_name);
        } else if (req_input->type == REQ_INP_ID) {
            ret = groups_get_handle_no_group(mem_ctx, domain,BE_FILTER_IDNUM,
                                             id_str);
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "Unexpected input type [%d].\n",
                                      req_input->type);
            ret = EINVAL;
            goto done;
        }
        break;
    case BE_REQ_BY_SECID:
        ret = EOK;
        break;
    case BE_REQ_BY_CERT:
        ret = EOK;
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, "Unexpected entry type [%d].\n", entry_type);
        ret = EINVAL;
    }

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Error while trying to remove user or group from cache.\n");
    }

    talloc_free(id_str);
    talloc_free(fq_name);
    return ret;
}

static void ipa_s2n_get_list_done(struct tevent_req  *subreq);
static void ipa_s2n_get_user_get_override_done(struct tevent_req *subreq);
static void ipa_s2n_get_user_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_s2n_get_user_state *state = tevent_req_data(req,
                                                struct ipa_s2n_get_user_state);
    int ret;
    char *retoid = NULL;
    struct berval *retdata = NULL;
    struct resp_attrs *attrs = NULL;
    struct berval *bv_req = NULL;
    char **missing_list = NULL;
    struct ldb_dn **group_dn_list = NULL;
    const char *sid_str;
    struct dp_id_data *ar;
    char *stat_info = NULL;

    ret = ipa_s2n_exop_recv(subreq, state, &retoid, &retdata);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (ret == ENOENT) {
            ret = s2n_remove_missing_object(state, state->dom,
                                            state->entry_type,
                                            state->req_input);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "s2n_remove_missing_object failed [%d].\n", ret);
            }
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "s2n exop request failed.\n");
            if (state->req_input->type == REQ_INP_CERT) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Maybe the server does not support lookups by "
                      "certificates.\n");
            }
        }
        goto done;
    }

    switch (state->request_type) {
    case REQ_FULL_WITH_MEMBERS:
    case REQ_FULL:
        ret = s2n_response_to_attrs(state, state->dom, retoid, retdata,
                                    &attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "s2n_response_to_attrs failed.\n");
            goto done;
        }

        if (!(strcasecmp(state->dom->name, attrs->domain_name) == 0 ||
              (state->dom->flat_name != NULL &&
               strcasecmp(state->dom->flat_name, attrs->domain_name) == 0))) {
            DEBUG(SSSDBG_OP_FAILURE, "Unexpected domain name returned, "
                                      "expected [%s] or [%s], got [%s].\n",
                         state->dom->name,
                         state->dom->flat_name == NULL ? "" :
                                                         state->dom->flat_name,
                         attrs->domain_name);
            ret = EINVAL;
            goto done;
        }

        state->attrs = attrs;

        if (attrs->response_type == RESP_USER_GROUPLIST) {

            DEBUG(SSSDBG_TRACE_FUNC, "Received [%zu] groups in group list "
                                     "from IPA Server\n", attrs->ngroups);

            for (size_t c = 0; c < attrs->ngroups; c++) {
                DEBUG(SSSDBG_TRACE_FUNC, "[%s].\n", attrs->groups[c]);
            }


            ret = get_group_dn_list(state,
                                    is_default_view(state->ipa_ctx->view_name),
                                    state->dom,
                                    attrs->ngroups, attrs->groups,
                                    &group_dn_list, &missing_list);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "get_group_dn_list failed.\n");
                goto done;
            }

            if (missing_list != NULL) {
                subreq = ipa_s2n_get_list_send(state, state->ev,
                                                 state->ipa_ctx, state->dom,
                                                 state->sh, state->exop_timeout,
                                                 BE_REQ_GROUP,
                                                 REQ_FULL_WITH_MEMBERS,
                                                 REQ_INP_NAME,
                                                 missing_list, NULL);
                if (subreq == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "ipa_s2n_get_list_send failed.\n");
                    ret = ENOMEM;
                    goto done;
                }
                tevent_req_set_callback(subreq, ipa_s2n_get_list_done,
                                        req);

                return;
            }
            break;
        } else if (attrs->response_type == RESP_GROUP_MEMBERS) {
            ret = process_members(state->dom,
                                  is_default_view(state->ipa_ctx->view_name),
                                  NULL, attrs->a.group.gr_mem, state,
                                  &missing_list);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "process_members failed.\n");
                goto done;
            }

            if (missing_list != NULL) {
                subreq = ipa_s2n_get_list_send(state, state->ev,
                                                 state->ipa_ctx, state->dom,
                                                 state->sh, state->exop_timeout,
                                                 BE_REQ_USER,
                                                 REQ_FULL_WITH_MEMBERS,
                                                 REQ_INP_NAME,
                                                 missing_list, NULL);
                if (subreq == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "ipa_s2n_get_list_send failed.\n");
                    ret = ENOMEM;
                    goto done;
                }
                tevent_req_set_callback(subreq, ipa_s2n_get_list_done,
                                        req);

                return;
            }
            break;
        }

        if (state->req_input->type == REQ_INP_SECID) {
            /* We already know the SID, we do not have to read it. */
            break;
        }

        state->request_type = REQ_SIMPLE;

        ret = s2n_encode_request(state, state->dom->name, state->entry_type,
                                 state->request_type, state->req_input,
                                 state->protocol,
                                 &bv_req, &stat_info);
        if (ret != EOK) {
            goto done;
        }

        subreq = ipa_s2n_exop_send(state, state->ev, state->sh, false,
                                   state->exop_timeout, bv_req, stat_info);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_exop_send failed.\n");
            ret = ENOMEM;
            goto done;
        }
        tevent_req_set_callback(subreq, ipa_s2n_get_user_done, req);

        return;

    case REQ_SIMPLE:
        ret = s2n_response_to_attrs(state, state->dom, retoid, retdata,
                                    &state->simple_attrs);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "s2n_response_to_attrs failed.\n");
            goto done;
        }

        if (state->simple_attrs->response_type == RESP_NAME_LIST
                && state->req_input->type == REQ_INP_CERT) {

            if (state->simple_attrs->name_list == NULL) {
                /* No results from sub-domains, nothing to do */
                ret = EOK;
                goto done;
            }

            state->mapped_attrs = sysdb_new_attrs(state);
            if (state->mapped_attrs == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs failed.\n");
                ret = ENOMEM;
                goto done;
            }

            ret = sysdb_attrs_add_base64_blob(state->mapped_attrs,
                                              SYSDB_USER_MAPPED_CERT,
                                              state->req_input->inp.cert);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_base64_blob failed.\n");
                goto done;
            }

            subreq = ipa_s2n_get_list_send(state, state->ev,
                                           state->ipa_ctx, state->dom,
                                           state->sh, state->exop_timeout,
                                           BE_REQ_USER,
                                           REQ_FULL_WITH_MEMBERS,
                                           REQ_INP_NAME,
                                           state->simple_attrs->name_list,
                                           state->mapped_attrs);
            if (subreq == NULL) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "ipa_s2n_get_list_send failed.\n");
                ret = ENOMEM;
                goto done;
            }
            tevent_req_set_callback(subreq, ipa_s2n_get_list_done,
                                    req);

            return;
        }

        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unexpected request type %d.\n", state->request_type);
        ret = EINVAL;
        goto done;
    }

    if (state->attrs == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing data of full request.\n");
        ret = EINVAL;
        goto done;
    }

    if (state->simple_attrs != NULL
            && state->simple_attrs->response_type == RESP_SID) {
        sid_str = state->simple_attrs->a.sid_str;
        ret = EOK;
    } else if (state->attrs->sysdb_attrs != NULL) {
        ret = sysdb_attrs_get_string(state->attrs->sysdb_attrs, SYSDB_SID_STR,
                                     &sid_str);
    } else if (state->req_input->type == REQ_INP_SECID) {
        sid_str = state->req_input->inp.secid;
        ret = EOK;
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "No SID available.\n");
        ret = ENOENT;
    }

    if (ret == ENOENT || is_default_view(state->ipa_ctx->view_name)) {
        ret = ipa_s2n_save_objects(state->dom, state->req_input, state->attrs,
                                   state->simple_attrs, NULL, NULL, NULL, true);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_save_objects failed.\n");
            goto done;
        }
    } else if (ret == EOK) {
        ret = get_dp_id_data_for_sid(state, sid_str, state->dom->name, &ar);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "get_dp_id_data_for_sid failed.\n");
            goto done;
        }

        subreq = ipa_get_trusted_override_send(state, state->ev,
                           state->ipa_ctx->sdap_id_ctx,
                           state->ipa_ctx->ipa_options,
                           dp_opt_get_string(state->ipa_ctx->ipa_options->basic,
                                             IPA_KRB5_REALM),
                           state->ipa_ctx->view_name,
                           ar);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_get_trusted_override_send failed.\n");
            ret = ENOMEM;
            goto done;
        }
        tevent_req_set_callback(subreq, ipa_s2n_get_user_get_override_done,
                                req);

        return;
    } else {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
        goto done;
    }

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    return;
}

static errno_t get_groups_dns(TALLOC_CTX *mem_ctx, struct sss_domain_info *dom,
                              char **name_list, char ***_dn_list)
{
    int ret;
    TALLOC_CTX *tmp_ctx;
    int c;
    struct sss_domain_info *root_domain;
    char **dn_list;
    size_t dn_list_c;
    struct ldb_message *msg;
    struct ldb_dn *user_base_dn = NULL;

    if (name_list == NULL) {
        *_dn_list = NULL;
        return EOK;
    }

    /* To handle cross-domain memberships we have to check the domain for
     * each group the member should be added or deleted. Since sub-domains
     * use fully-qualified names by default any short name can only belong
     * to the root/head domain. find_domain_by_object_name() will return
     * the domain given in the first argument if the second argument is a
     * a short name hence we always use root_domain as first argument. */
    root_domain = get_domains_head(dom);
    if (root_domain->fqnames) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Root domain uses fully-qualified names, " \
              "objects might not be correctly added to groups with " \
              "short names.\n");
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    for (c = 0; name_list[c] != NULL; c++);

    dn_list = talloc_zero_array(tmp_ctx, char *, c + 1);
    if (dn_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    dn_list_c = 0;
    for (c = 0; name_list[c] != NULL; c++) {
        dom = find_domain_by_object_name(root_domain, name_list[c]);
        if (dom == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot find domain for [%s].\n", name_list[c]);
            ret = ENOENT;
            goto done;
        }

        /* If the group name is overridden in the default view we have to
         * search for the name and cannot construct it because the extdom
         * plugin will return the overridden name but the DN of the related
         * group object in the cache will contain the original name. */

        ret = sysdb_search_group_by_name(tmp_ctx, dom, name_list[c], NULL,
                                         &msg);
        if (ret == EOK) {
            talloc_free(user_base_dn);
            user_base_dn = sysdb_user_base_dn(tmp_ctx, dom);
            if (user_base_dn == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_user_base_dn failed.\n");
                ret = ENOMEM;
                goto done;
            }
            if (ldb_dn_compare_base(user_base_dn, msg->dn) == 0) {
                DEBUG(SSSDBG_TRACE_FUNC, "Skipping user private group [%s].\n",
                                         ldb_dn_get_linearized(msg->dn));
                continue;
            }

            dn_list[dn_list_c] = ldb_dn_alloc_linearized(dn_list, msg->dn);
        } else {
            /* best effort, try to construct the DN */
            DEBUG(SSSDBG_TRACE_FUNC,
                  "sysdb_search_group_by_name failed with [%d], "
                  "generating DN for [%s] in domain [%s].\n",
                  ret, name_list[c], dom->name);
            dn_list[dn_list_c] = sysdb_group_strdn(dn_list, dom->name,
                                                   name_list[c]);
        }
        if (dn_list[dn_list_c] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_alloc_linearized failed.\n");
            ret = ENOMEM;
            goto done;
        }

        DEBUG(SSSDBG_TRACE_ALL, "Added [%s][%s].\n", name_list[c],
                                                     dn_list[dn_list_c]);
        dn_list_c++;
    }

    *_dn_list = talloc_steal(mem_ctx, dn_list);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t ipa_s2n_save_objects(struct sss_domain_info *dom,
                                    struct req_input *req_input,
                                    struct resp_attrs *attrs,
                                    struct resp_attrs *simple_attrs,
                                    const char *view_name,
                                    struct sysdb_attrs *override_attrs,
                                    struct sysdb_attrs *mapped_attrs,
                                    bool update_initgr_timeout)
{
    int ret;
    time_t now;
    struct sss_nss_homedir_ctx homedir_ctx;
    char *name = NULL;
    char *upn = NULL;
    gid_t gid;
    gid_t orig_gid = 0;
    TALLOC_CTX *tmp_ctx;
    const char *sid_str;
    const char *tmp_str;
    struct ldb_result *res;
    enum sysdb_member_type type;
    char **sysdb_grouplist;
    char **add_groups_dns;
    char **del_groups_dns;
    char **groups_dns;
    bool in_transaction = false;
    int tret;
    struct sysdb_attrs *gid_override_attrs = NULL;
    struct ldb_message *msg;
    struct ldb_message_element *el = NULL;

    /* The list of elements that might be missing are:
     * - SYSDB_ORIG_MEMBEROF
     * - SYSDB_SSH_PUBKEY
     * - SYSDB_USER_CERT
     * Note that the list includes the trailing NULL at the end. */
    size_t missing_count = 0;
    const char *missing[] = {NULL, NULL, NULL, NULL};

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    now = time(NULL);

    if (attrs->sysdb_attrs == NULL) {
        attrs->sysdb_attrs = sysdb_new_attrs(attrs);
        if (attrs->sysdb_attrs == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    if (attrs->sysdb_attrs != NULL) {
        ret = sysdb_attrs_get_string(attrs->sysdb_attrs,
                                     ORIGINALAD_PREFIX SYSDB_NAME, &tmp_str);
        if (ret == EOK) {
            name = talloc_strdup(tmp_ctx, tmp_str);
            if (name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
            DEBUG(SSSDBG_TRACE_ALL, "Found original AD name [%s].\n", name);
        } else if (ret == ENOENT) {
            name = NULL;
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_string(attrs->sysdb_attrs,
                                     SYSDB_DEFAULT_OVERRIDE_NAME, &tmp_str);
        if (ret == EOK) {
            ret = sysdb_attrs_add_lc_name_alias_safe(attrs->sysdb_attrs,
                                                     tmp_str);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sysdb_attrs_add_lc_name_alias_safe failed.\n");
                goto done;
            }
        } else if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_string(attrs->sysdb_attrs, SYSDB_UPN, &tmp_str);
        if (ret == EOK) {
            upn = talloc_strdup(tmp_ctx, tmp_str);
            if (upn == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto done;
            }
            DEBUG(SSSDBG_TRACE_ALL, "Found original AD upn [%s].\n", upn);
        } else if (ret == ENOENT) {
            upn = NULL;
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto done;
        }
    }

    if (strcmp(dom->name, attrs->domain_name) != 0) {
        dom = find_domain_by_name(get_domains_head(dom),
                                  attrs->domain_name, true);
        if (dom == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                    "Cannot find domain: [%s]\n", attrs->domain_name);
            ret = EINVAL;
            goto done;
        }
    }

    switch (attrs->response_type) {
        case RESP_USER:
        case RESP_USER_GROUPLIST:
            type = SYSDB_MEMBER_USER;
            if (dom->subdomain_homedir
                    && attrs->a.user.pw_dir == NULL) {
                memset(&homedir_ctx, 0, sizeof(homedir_ctx));
                homedir_ctx.username = attrs->a.user.pw_name;
                homedir_ctx.uid = attrs->a.user.pw_uid;
                homedir_ctx.domain = dom->name;
                homedir_ctx.flatname = dom->flat_name;
                homedir_ctx.config_homedir_substr = dom->homedir_substr;

                attrs->a.user.pw_dir = expand_homedir_template(attrs,
                                                  dom->subdomain_homedir,
                                                  dom->case_preserve,
                                                  &homedir_ctx);
                if (attrs->a.user.pw_dir == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
            }

            if (name == NULL) {
                name = attrs->a.user.pw_name;
            }

            ret = sysdb_attrs_add_lc_name_alias_safe(attrs->sysdb_attrs, name);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sysdb_attrs_add_lc_name_alias_safe failed.\n");
                goto done;
            }

            if (req_input->type == REQ_INP_SECID) {
                ret = sysdb_attrs_add_string_safe(attrs->sysdb_attrs,
                                                  SYSDB_SID_STR,
                                                  req_input->inp.secid);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_attrs_add_string failed.\n");
                    goto done;
                }
            }

            if (simple_attrs != NULL
                    && simple_attrs->response_type == RESP_SID) {
                ret = sysdb_attrs_add_string_safe(attrs->sysdb_attrs,
                                                  SYSDB_SID_STR,
                                                  simple_attrs->a.sid_str);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_attrs_add_string failed.\n");
                    goto done;
                }
            }

            if (attrs->response_type == RESP_USER_GROUPLIST
                    && update_initgr_timeout) {
                /* Since RESP_USER_GROUPLIST contains all group memberships it
                 * is effectively an initgroups request hence
                 * SYSDB_INITGR_EXPIRE will be set.*/
                ret = sysdb_attrs_add_time_t(attrs->sysdb_attrs,
                                             SYSDB_INITGR_EXPIRE,
                                             time(NULL) + dom->user_timeout);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_attrs_add_time_t failed.\n");
                    goto done;
                }
            }

            gid = 0;
            if (sss_domain_is_mpg(dom) == false) {
                gid = attrs->a.user.pw_gid;
            } else {
                /* The extdom plugin always returns the objects with the
                 * default view applied. Since the GID is handled specially
                 * for MPG domains we have add any overridden GID separately.
                 */
                ret = sysdb_attrs_get_uint32_t(attrs->sysdb_attrs,
                                               ORIGINALAD_PREFIX SYSDB_GIDNUM,
                                               &orig_gid);
                if (ret == EOK || ret == ENOENT) {
                    if ((orig_gid != 0 && orig_gid != attrs->a.user.pw_gid)
                            || attrs->a.user.pw_uid != attrs->a.user.pw_gid) {

                        gid_override_attrs = sysdb_new_attrs(tmp_ctx);
                        if (gid_override_attrs == NULL) {
                            DEBUG(SSSDBG_OP_FAILURE,
                                  "sysdb_new_attrs failed.\n");
                            ret = ENOMEM;
                            goto done;
                        }

                        ret = sysdb_attrs_add_uint32(gid_override_attrs,
                                                     SYSDB_GIDNUM,
                                                     attrs->a.user.pw_gid);
                        if (ret != EOK) {
                            DEBUG(SSSDBG_OP_FAILURE,
                                  "sysdb_attrs_add_uint32 failed.\n");
                            goto done;
                        }
                    }
                } else {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_attrs_get_uint32_t failed.\n");
                    goto done;
                }
            }

            ret = sysdb_attrs_get_el_ext(attrs->sysdb_attrs,
                                         SYSDB_ORIG_MEMBEROF, false, &el);
            if (ret == ENOENT) {
                missing[missing_count++] = SYSDB_ORIG_MEMBEROF;
            }

            ret = sysdb_attrs_get_el_ext(attrs->sysdb_attrs,
                                         SYSDB_SSH_PUBKEY, false, &el);
            if (ret == ENOENT) {
                missing[missing_count++] = SYSDB_SSH_PUBKEY;
            }

            ret = sysdb_attrs_get_el_ext(attrs->sysdb_attrs,
                                         SYSDB_USER_CERT, false, &el);
            if (ret == ENOENT) {
                missing[missing_count++] = SYSDB_USER_CERT;
            }

            ret = sysdb_transaction_start(dom->sysdb);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
                goto done;
            }
            in_transaction = true;

            ret = sysdb_store_user(dom, name, NULL,
                                   attrs->a.user.pw_uid,
                                   gid, attrs->a.user.pw_gecos,
                                   attrs->a.user.pw_dir, attrs->a.user.pw_shell,
                                   NULL, attrs->sysdb_attrs,
                                   missing[0] == NULL ? NULL
                                                      : discard_const(missing),
                                   dom->user_timeout, now);
            if (ret == EEXIST && sss_domain_is_mpg(dom) == true) {
                /* This handles the case where getgrgid() was called for
                 * this user, so a group was created in the cache
                 */
                ret = sysdb_search_group_by_name(tmp_ctx, dom, name, NULL, &msg);
                if (ret != EOK) {
                    /* Fail even on ENOENT, the group must be around */
                    DEBUG(SSSDBG_OP_FAILURE,
                          "Could not delete MPG group [%d]: %s\n",
                          ret, sss_strerror(ret));
                    goto done;
                }

                ret = sysdb_delete_group(dom, NULL, attrs->a.user.pw_uid);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_delete_group failed for MPG group [%d]: %s\n",
                          ret, sss_strerror(ret));
                    goto done;
                }

                ret = sysdb_store_user(dom, name, NULL,
                                       attrs->a.user.pw_uid,
                                       gid, attrs->a.user.pw_gecos,
                                       attrs->a.user.pw_dir,
                                       attrs->a.user.pw_shell,
                                       NULL, attrs->sysdb_attrs, NULL,
                                       dom->user_timeout, now);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_store_user failed for MPG user [%d]: %s\n",
                          ret, sss_strerror(ret));
                    goto done;
                }
            } else if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sysdb_store_user failed [%d]: %s\n",
                      ret, sss_strerror(ret));
                goto done;
            }

            if (mapped_attrs != NULL) {
                ret = sysdb_set_user_attr(dom, name, mapped_attrs,
                                          SYSDB_MOD_ADD);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "sysdb_set_user_attr failed.\n");
                    goto done;
                }
            }

            if (gid_override_attrs != NULL) {
                ret = sysdb_set_user_attr(dom, name, gid_override_attrs,
                                          SYSDB_MOD_REP);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "sysdb_set_user_attr failed.\n");
                    goto done;
                }
            }

            if (attrs->response_type == RESP_USER_GROUPLIST) {
                ret = get_sysdb_grouplist_dn(tmp_ctx, dom->sysdb, dom, name,
                                             &sysdb_grouplist);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "get_sysdb_grouplist failed.\n");
                    goto done;
                }

                ret = get_groups_dns(tmp_ctx, dom, attrs->groups, &groups_dns);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "get_groups_dns failed.\n");
                    goto done;
                }

                ret = diff_string_lists(tmp_ctx, groups_dns,
                                        sysdb_grouplist, &add_groups_dns,
                                        &del_groups_dns, NULL);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "diff_string_lists failed.\n");
                    goto done;
                }

                DEBUG(SSSDBG_TRACE_INTERNAL, "Updating memberships for %s\n",
                                             name);
                ret = sysdb_update_members_dn(dom, name, SYSDB_MEMBER_USER,
                                          (const char *const *) add_groups_dns,
                                          (const char *const *) del_groups_dns);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Membership update failed [%d]: %s\n",
                                               ret, sss_strerror(ret));
                    goto done;
                }
            }

            ret = sysdb_transaction_commit(dom->sysdb);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
                goto done;
            }
            in_transaction = false;

            break;
        case RESP_GROUP:
        case RESP_GROUP_MEMBERS:
            type = SYSDB_MEMBER_GROUP;

            if (name == NULL) {
                name = attrs->a.group.gr_name;
            }

            DEBUG(SSSDBG_TRACE_FUNC, "Processing group %s\n", name);

            ret = sysdb_attrs_add_lc_name_alias_safe(attrs->sysdb_attrs, name);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sysdb_attrs_add_lc_name_alias_safe failed.\n");
                goto done;
            }

            /* We might already have the SID from other sources hence
             * sysdb_attrs_add_string_safe is used to avoid double entries. */
            if (req_input->type == REQ_INP_SECID) {
                ret = sysdb_attrs_add_string_safe(attrs->sysdb_attrs,
                                                  SYSDB_SID_STR,
                                                  req_input->inp.secid);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_attrs_add_string failed.\n");
                    goto done;
                }
            }

            if (simple_attrs != NULL
                && simple_attrs->response_type == RESP_SID) {
                ret = sysdb_attrs_add_string_safe(attrs->sysdb_attrs,
                                                  SYSDB_SID_STR,
                                                  simple_attrs->a.sid_str);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "sysdb_attrs_add_string failed.\n");
                    goto done;
                }
            }

            ret = process_members(dom, is_default_view(view_name),
                                  attrs->sysdb_attrs, attrs->a.group.gr_mem,
                                  NULL, NULL);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "process_members failed.\n");
                goto done;
            }

            ret = sysdb_store_group(dom, name, attrs->a.group.gr_gid,
                                    attrs->sysdb_attrs, dom->group_timeout,
                                    now);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_store_group failed.\n");
                goto done;
            }
            break;
        default:
            DEBUG(SSSDBG_OP_FAILURE, "Unexpected response type [%d].\n",
                                      attrs->response_type);
            ret = EINVAL;
            goto done;
    }

    ret = sysdb_attrs_get_string(attrs->sysdb_attrs, SYSDB_SID_STR, &sid_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot find SID of object.\n");
        if (name != NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Object [%s] has no SID, please check the "
                  "ipaNTSecurityIdentifier attribute on the server-side.\n",
                  name);
        }
        goto done;
    }

    ret = sysdb_search_object_by_sid(tmp_ctx, dom, sid_str, NULL, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot find object with override with SID [%s].\n", sid_str);
        goto done;
    }

    if (!is_default_view(view_name)) {
        /* For the default view the data return by the extdom plugin already
         * contains all needed data and it is not expected to have a separate
         * override object. */
        ret = sysdb_store_override(dom, view_name, type, override_attrs,
                                   res->msgs[0]->dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_store_override failed.\n");
            goto done;
        }
    }

done:
    if (in_transaction) {
        tret = sysdb_transaction_cancel(dom->sysdb);
        if (tret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to cancel transaction\n");
        }
    }

    talloc_free(tmp_ctx);

    return ret;
}

static void ipa_s2n_get_list_done(struct tevent_req  *subreq)
{
    int ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_s2n_get_user_state *state = tevent_req_data(req,
                                                struct ipa_s2n_get_user_state);
    const char *sid_str;
    struct dp_id_data *ar;

    ret = ipa_s2n_get_list_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "s2n get_fqlist request failed.\n");
        tevent_req_error(req, ret);
        return;
    }

    if (state->attrs == NULL) {
        /* If this is a request by certificate we are done */
        if (state->req_input->type == REQ_INP_CERT) {
            tevent_req_done(req);
        } else {
            tevent_req_error(req, EINVAL);
        }
        return;
    }

    ret = sysdb_attrs_get_string(state->attrs->sysdb_attrs, SYSDB_SID_STR,
                                 &sid_str);
    if (ret == ENOENT) {
        ret = ipa_s2n_save_objects(state->dom, state->req_input, state->attrs,
                                   state->simple_attrs, NULL, NULL, NULL, true);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_save_objects failed.\n");
            goto fail;
        }
        tevent_req_done(req);
        return;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
        goto fail;
    }

    ret = get_dp_id_data_for_sid(state, sid_str, state->dom->name, &ar);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "get_dp_id_data_for_sid failed.\n");
        goto fail;
    }

    if (state->override_attrs == NULL
            && !is_default_view(state->ipa_ctx->view_name)) {
        subreq = ipa_get_trusted_override_send(state, state->ev,
                           state->ipa_ctx->sdap_id_ctx,
                           state->ipa_ctx->ipa_options,
                           dp_opt_get_string(state->ipa_ctx->ipa_options->basic,
                                             IPA_KRB5_REALM),
                           state->ipa_ctx->view_name,
                           ar);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_get_trusted_override_send failed.\n");
            ret = ENOMEM;
            goto fail;
        }
        tevent_req_set_callback(subreq, ipa_s2n_get_user_get_override_done,
                                req);
    } else {
        ret = ipa_s2n_save_objects(state->dom, state->req_input, state->attrs,
                                   state->simple_attrs,
                                   state->ipa_ctx->view_name,
                                   state->override_attrs, NULL, true);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_save_objects failed.\n");
            tevent_req_error(req, ret);
            return;
        }

        tevent_req_done(req);
    }

    return;

fail:
    tevent_req_error(req, ret);
    return;
}

static void ipa_s2n_get_user_get_override_done(struct tevent_req *subreq)
{
    int ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_s2n_get_user_state *state = tevent_req_data(req,
                                                struct ipa_s2n_get_user_state);
    struct sysdb_attrs *override_attrs = NULL;

    ret = ipa_get_trusted_override_recv(subreq, NULL, state, &override_attrs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "IPA override lookup failed: %d\n", ret);
        tevent_req_error(req, ret);
        return;
    }

    ret = ipa_s2n_save_objects(state->dom, state->req_input, state->attrs,
                               state->simple_attrs, state->ipa_ctx->view_name,
                               override_attrs, NULL, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_save_objects failed.\n");
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

int ipa_s2n_get_acct_info_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct ipa_get_subdom_acct_process_pac_state {
    struct tevent_context *ev;
    struct sdap_handle *sh;
    struct sss_domain_info *dom;
    char *username;

    size_t num_missing_sids;
    char **missing_sids;
    size_t num_cached_groups;
    char **cached_groups;
};

static void ipa_get_subdom_acct_process_pac_done(struct tevent_req *subreq);

struct tevent_req *ipa_get_subdom_acct_process_pac_send(TALLOC_CTX *mem_ctx,
                                                   struct tevent_context *ev,
                                                   struct sdap_handle *sh,
                                                   struct ipa_id_ctx *ipa_ctx,
                                                   struct sss_domain_info *dom,
                                                   struct ldb_message *user_msg)
{
    int ret;
    struct ipa_get_subdom_acct_process_pac_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    char *user_sid;
    char *primary_group_sid;
    size_t num_sids;
    char **group_sids;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_get_subdom_acct_process_pac_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    state->ev = ev;
    state->sh = sh;
    state->dom = dom;

    ret = ad_get_pac_data_from_user_entry(state, user_msg,
                                     ipa_ctx->sdap_id_ctx->opts->idmap_ctx->map,
                                     &state->username,
                                     &user_sid, &primary_group_sid,
                                     &num_sids, &group_sids);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ad_get_pac_data_from_user_entry failed.\n");
        goto done;
    }

    ret = sdap_ad_tokengroups_get_posix_members(state, state->dom,
                                                num_sids, group_sids,
                                                &state->num_missing_sids,
                                                &state->missing_sids,
                                                &state->num_cached_groups,
                                                &state->cached_groups);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "sdap_ad_tokengroups_get_posix_members failed.\n");
        goto done;
    }


    if (state->num_missing_sids == 0) {
        ret = sdap_ad_tokengroups_update_members(state->username,
                                                 state->dom->sysdb,
                                                 state->dom,
                                                 state->cached_groups);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Membership update failed [%d]: %s\n",
                                         ret, strerror(ret));
        }

        goto done;
    }


    subreq = ipa_s2n_get_list_send(state, state->ev, ipa_ctx, state->dom,
                               state->sh,
                               dp_opt_get_int(ipa_ctx->sdap_id_ctx->opts->basic,
                                              SDAP_SEARCH_TIMEOUT),
                               BE_REQ_BY_SECID, REQ_FULL, REQ_INP_SECID,
                               state->missing_sids, NULL);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_s2n_get_list_send failed.\n");
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, ipa_get_subdom_acct_process_pac_done, req);

    return req;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

static void ipa_get_subdom_acct_process_pac_done(struct tevent_req *subreq)
{
    int ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_get_subdom_acct_process_pac_state *state = tevent_req_data(req,
                                  struct ipa_get_subdom_acct_process_pac_state);
    char **cached_groups;
    size_t num_cached_groups;

    ret = ipa_s2n_get_list_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "s2n get_fqlist request failed.\n");
        tevent_req_error(req, ret);
        return;
    }

    /* from ad_pac.c */
    ret = sdap_ad_tokengroups_get_posix_members(state, state->dom,
                                                state->num_missing_sids,
                                                state->missing_sids,
                                                NULL, NULL,
                                                &num_cached_groups,
                                                &cached_groups);
    if (ret != EOK){
        DEBUG(SSSDBG_MINOR_FAILURE,
              "sdap_ad_tokengroups_get_posix_members failed [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    state->cached_groups = concatenate_string_array(state,
                                                    state->cached_groups,
                                                    state->num_cached_groups,
                                                    cached_groups,
                                                    num_cached_groups);
    if (state->cached_groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* update membership of existing groups */
    ret = sdap_ad_tokengroups_update_members(state->username,
                                             state->dom->sysdb,
                                             state->dom,
                                             state->cached_groups);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Membership update failed [%d]: %s\n",
                                     ret, strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }

    return;
}

errno_t ipa_get_subdom_acct_process_pac_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
