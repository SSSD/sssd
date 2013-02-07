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
#include "db/sysdb.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/ldap_common.h"

enum input_types {
    INP_SID = 1,
    INP_NAME,
    INP_POSIX_UID,
    INP_POSIX_GID
};

enum request_types {
    REQ_SIMPLE = 1,
    REQ_FULL
};

enum response_types {
    RESP_SID = 1,
    RESP_NAME,
    RESP_USER,
    RESP_GROUP
};

/* ==Sid2Name Extended Operation============================================= */
#define EXOP_SID2NAME_OID "2.16.840.1.113730.3.8.10.4"

struct ipa_s2n_exop_state {
    struct sdap_handle *sh;

    struct sdap_op *op;

    int result;
    char *retoid;
    struct berval *retdata;
};

static void ipa_s2n_exop_done(struct sdap_op *op,
                           struct sdap_msg *reply,
                           int error, void *pvt);

static struct tevent_req *ipa_s2n_exop_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct sdap_handle *sh,
                                            struct berval *bv)
{
    struct tevent_req *req = NULL;
    struct ipa_s2n_exop_state *state;
    int ret;
    int msgid;

    req = tevent_req_create(mem_ctx, &state, struct ipa_s2n_exop_state);
    if (!req) return NULL;

    state->sh = sh;
    state->result = LDAP_OPERATIONS_ERROR;
    state->retoid = NULL;
    state->retdata = NULL;

    DEBUG(SSSDBG_TRACE_FUNC, ("Executing extended operation\n"));

    ret = ldap_extended_operation(state->sh->ldap, EXOP_SID2NAME_OID,
                                  bv, NULL, NULL, &msgid);
    if (ret == -1 || msgid == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("ldap_extended_operation failed\n"));
        goto fail;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, ("ldap_extended_operation sent, msgid = %d\n", msgid));

    /* FIXME: get timeouts from configuration, for now 10 secs. */
    ret = sdap_op_add(state, ev, state->sh, msgid, ipa_s2n_exop_done, req, 10,
                      &state->op);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to set up operation!\n"));
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, EIO);
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

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    ret = ldap_parse_result(state->sh->ldap, reply->msg,
                            &state->result, &errmsg, NULL, NULL,
                            NULL, 0);
    if (ret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, ("ldap_parse_result failed (%d)\n", state->op->msgid));
        ret = EIO;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("ldap_extended_operation result: %s(%d), %s\n",
            sss_ldap_err2string(state->result), state->result, errmsg));

    if (state->result != LDAP_SUCCESS) {
        ret = EIO;
        goto done;
    }

    ret = ldap_parse_extended_result(state->sh->ldap, reply->msg,
                                      &retoid, &retdata, 0);
    if (ret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, ("ldap_parse_extendend_result failed (%d)\n", ret));
        ret = EIO;
        goto done;
    }

    state->retoid = talloc_strdup(state, retoid);
    if (state->retoid == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    state->retdata = talloc(state, struct berval);
    if (state->retdata == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc failed.\n"));
        ret = ENOMEM;
        goto done;
    }
    state->retdata->bv_len = retdata->bv_len;
    state->retdata->bv_val = talloc_memdup(state->retdata, retdata->bv_val,
                                           retdata->bv_len);
    if (state->retdata->bv_val == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_memdup failed.\n"));
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
                             enum sdap_result *result, char **retoid,
                             struct berval **retdata)
{
    struct ipa_s2n_exop_state *state = tevent_req_data(req,
                                                    struct ipa_s2n_exop_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (state->result == LDAP_SUCCESS) {
        *result = SDAP_SUCCESS;
        *retoid = talloc_steal(mem_ctx, state->retoid);
        *retdata = talloc_steal(mem_ctx, state->retdata);
    } else {
        *result = SDAP_ERROR;
    }

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
                                  const char *name,
                                  uint32_t id,
                                  struct berval **_bv)
{
    BerElement *ber = NULL;
    int ret;

    ber = ber_alloc_t( LBER_USE_DER );
    if (ber == NULL) {
        return ENOMEM;
    }

    switch (entry_type) {
        case BE_REQ_USER:
            if (name != NULL) {
                ret = ber_printf(ber, "{ee{ss}}", INP_NAME, REQ_FULL,
                                                  domain_name, name);
            } else {
                ret = ber_printf(ber, "{ee{si}}", INP_POSIX_UID, REQ_FULL,
                                                  domain_name, id);
            }
            break;
        case BE_REQ_GROUP:
            if (name != NULL) {
                ret = ber_printf(ber, "{ee{ss}}", INP_NAME, REQ_FULL,
                                                  domain_name, name);
            } else {
                ret = ber_printf(ber, "{ee{si}}", INP_POSIX_GID, REQ_FULL,
                                                  domain_name, id);
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
    if (ret == -1) {
        ret = EFAULT;
        goto done;
    }

    ret = EOK;

done:
    ber_free(ber, 1);

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
 *        posix_group (4)
 *    },
 *    data OutputData
 * }
 *
 * OutputData ::= CHOICE {
 *    sid OCTET STRING,
 *    name NameDomainData,
 *    user PosixUser,
 *    group PosixGroup
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
 * Since we always request the full data set (REQ_FULL), i.e user/group name,
 * domain name and corresponding unix id, only PosixUser (RESP_USER) and
 * PosixGroup (RESP_GROUP) are handled by s2n_response_to_attrs().
 */

struct resp_attrs {
    enum response_types response_type;
    char *domain_name;
    union {
        struct passwd user;
        struct group group;
    } a;
};

static errno_t s2n_response_to_attrs(TALLOC_CTX *mem_ctx,
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

    if (retoid == NULL || retdata == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Missing OID or data.\n"));
        return EINVAL;
    }

    if (strcmp(retoid, EXOP_SID2NAME_OID) != 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Result has wrong OID, expected [%s], got [%s].\n",
              EXOP_SID2NAME_OID, retoid));
        return EINVAL;
    }

    ber = ber_init(retdata);
    if (ber == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("ber_init failed.\n"));
        return EINVAL;
    }

    tag = ber_scanf(ber, "{e", &type);
    if (tag == LBER_ERROR) {
        DEBUG(SSSDBG_OP_FAILURE, ("ber_scanf failed.\n"));
        ret = EINVAL;
        goto done;
    }

    attrs = talloc_zero(mem_ctx, struct resp_attrs);
    if (attrs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_zero failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    switch (type) {
        case RESP_USER:
            tag = ber_scanf(ber, "{aaii}}", &domain_name, &name, &uid, &gid);
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, ("ber_scanf failed.\n"));
                ret = EINVAL;
                goto done;
            }

            /* Winbind is not consistent with the case of the returned user
             * name. In general all names should be lower case but there are
             * bug in some version of winbind which might lead to upper case
             * letters in the name. To be on the safe side we explicitly
             * lowercase the name. */
            attrs->a.user.pw_name = sss_tc_utf8_str_tolower(attrs, name);
            if (attrs->a.user.pw_name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
                ret = ENOMEM;
                goto done;
            }

            attrs->a.user.pw_uid = uid;
            attrs->a.user.pw_gid = gid;

            break;
        case RESP_GROUP:
            tag = ber_scanf(ber, "{aai}}", &domain_name, &name, &gid);
            if (tag == LBER_ERROR) {
                DEBUG(SSSDBG_OP_FAILURE, ("ber_scanf failed.\n"));
                ret = EINVAL;
                goto done;
            }

            attrs->a.group.gr_name = talloc_strdup(attrs, name);
            if (attrs->a.group.gr_name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
                ret = ENOMEM;
                goto done;
            }

            attrs->a.group.gr_gid = gid;

            break;
        default:
            DEBUG(SSSDBG_OP_FAILURE, ("Unexpected response type [%d].\n",
                                      type));
            ret = EINVAL;
            goto done;
    }

    attrs->response_type = type;
    attrs->domain_name = talloc_strdup(attrs, domain_name);
    if (attrs->domain_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;

done:
    ber_memfree(domain_name);
    ber_memfree(name);
    ber_free(ber, 1);

    if (ret == EOK) {
        *resp_attrs = attrs;
    } else {
        talloc_free(attrs);
    }

    return ret;
}

struct ipa_s2n_get_user_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sss_domain_info *dom;
    struct sdap_handle *sh;
    const char **expected_attrs;
};

static void ipa_s2n_get_user_done(struct tevent_req *subreq);

struct tevent_req *ipa_s2n_get_acct_info_send(TALLOC_CTX *mem_ctx,
                                              struct tevent_context *ev,
                                              struct sdap_options *opts,
                                              struct sss_domain_info *dom,
                                              struct sdap_handle *sh,
                                              const char **attrs,
                                              int entry_type,
                                              const char *name,
                                              uint32_t id)
{
    struct ipa_s2n_get_user_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct berval *bv_req = NULL;
    int ret = EFAULT;

    if ((name == NULL && id == 0) || (name != NULL && id != 0)) {
        DEBUG(SSSDBG_OP_FAILURE, ("Either a user name or a uid expected, "
                                  "not both or nothing.\n"));
        return NULL;
    }

    req = tevent_req_create(mem_ctx, &state, struct ipa_s2n_get_user_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->opts = opts;
    state->dom = dom;
    state->sh = sh;
    state->expected_attrs = attrs;

    ret = s2n_encode_request(state, dom->name, entry_type, name, id, &bv_req);
    if (ret != EOK) {
        goto fail;
    }

    subreq = ipa_s2n_exop_send(state, state->ev, state->sh, bv_req);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("ipa_s2n_exop_send failed.\n"));
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

static void ipa_s2n_get_user_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_s2n_get_user_state *state = tevent_req_data(req,
                                                struct ipa_s2n_get_user_state);
    int ret;
    enum sdap_result result;
    char *retoid = NULL;
    struct berval *retdata = NULL;
    struct resp_attrs *attrs;
    time_t now;
    uint64_t timeout = 10*60*60; /* FIXME: find a better timeout ! */
    const char *homedir = NULL;
    struct sysdb_attrs *user_attrs = NULL;
    char *name;
    char *realm;
    char *upn;

    ret = ipa_s2n_exop_recv(subreq, state, &result, &retoid, &retdata);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("s2n exop request failed.\n"));
        goto done;
    }

    ret = s2n_response_to_attrs(state, retoid, retdata, &attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("s2n_response_to_attrs failed.\n"));
        goto done;
    }

    if (!(strcasecmp(state->dom->name, attrs->domain_name) == 0 ||
          (state->dom->flat_name != NULL &&
           strcasecmp(state->dom->flat_name, attrs->domain_name) == 0))) {
        DEBUG(SSSDBG_OP_FAILURE, ("Unexpected domain name returned, "
                                  "expected [%s] or [%s], got [%s].\n",
                     state->dom->name,
                     state->dom->flat_name == NULL ? "" : state->dom->flat_name,
                     attrs->domain_name));
        ret = EINVAL;
        goto done;
    }

    now = time(NULL);

    switch (attrs->response_type) {
        case RESP_USER:
            if (state->dom->subdomain_homedir) {
                homedir =  expand_homedir_template(state,
                                                   state->dom->subdomain_homedir,
                                                   attrs->a.user.pw_name,
                                                   attrs->a.user.pw_uid,
                                                   NULL,
                                                   state->dom->name);
                if (homedir == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
            }

            user_attrs = sysdb_new_attrs(state);
            if (user_attrs == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("sysdb_new_attrs failed.\n"));
                ret = ENOMEM;
                goto done;
            }

            /* we always use the fully qualified name for subdomain users */
            name = talloc_asprintf(state, state->dom->names->fq_fmt,
                                   attrs->a.user.pw_name, state->dom->name);
            if (!name) {
                DEBUG(SSSDBG_OP_FAILURE, ("failed to format user name.\n"));
                ret = ENOMEM;
                goto done;
            }

            ret = sysdb_attrs_add_string(user_attrs, SYSDB_NAME_ALIAS, name);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_add_string failed.\n"));
                goto done;
            }

            /* We also have to store a fake UPN here, because otherwise the
             * krb5 child later won't be able to properly construct one as
             * the username is fully qualified but the child doesn't have
             * access to the regex to deconstruct it */
            /* FIXME: The real UPN is available from the PAC, we should get
             * it from there. */
            realm = get_uppercase_realm(state, state->dom->name);
            if (!realm) {
                DEBUG(SSSDBG_OP_FAILURE, ("failed to get realm.\n"));
                ret = ENOMEM;
                goto done;
            }
            upn = talloc_asprintf(state, "%s@%s",
                                  attrs->a.user.pw_name, realm);
            if (!upn) {
                DEBUG(SSSDBG_OP_FAILURE, ("failed to format UPN.\n"));
                ret = ENOMEM;
                goto done;
            }

            ret = sysdb_attrs_add_string(user_attrs, SYSDB_UPN, upn);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_add_string failed.\n"));
                goto done;
            }

            ret = sysdb_store_domuser(state->dom, name, NULL,
                                      attrs->a.user.pw_uid,
                                      0, NULL, /* gecos */
                                      homedir, NULL,
                                      user_attrs, NULL, timeout, now);
            break;
        case RESP_GROUP:
            /* we always use the fully qualified name for subdomain users */
            name = talloc_asprintf(state, state->dom->names->fq_fmt,
                                   attrs->a.group.gr_name, state->dom->name);
            if (!name) {
                DEBUG(SSSDBG_OP_FAILURE, ("failed to format user name,\n"));
                ret = ENOMEM;
                goto done;
            }

            ret = sysdb_store_domgroup(state->dom, name,
                                       attrs->a.group.gr_gid, NULL, timeout,
                                       now);
            break;
        default:
            DEBUG(SSSDBG_OP_FAILURE, ("Unexpected response type [%d].\n",
                                      attrs->response_type));
            ret = EINVAL;
            goto done;
    }


done:
    talloc_free(user_attrs);
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    return;
}

int ipa_s2n_get_acct_info_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
