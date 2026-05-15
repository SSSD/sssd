/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#include "responder/nss/nss_protocol.h"
#include "util/sss_nss.h"

static uint32_t
sss_nss_get_gid(struct sss_domain_info *domain,
                struct ldb_message *msg)
{
    uint32_t gid;

    /* First, try to return overridden gid. */
    if (DOM_HAS_VIEWS(domain)) {
        gid = ldb_msg_find_attr_as_uint64(msg, OVERRIDE_PREFIX SYSDB_GIDNUM,
                                          0);
        if (gid != 0) {
            return gid;
        }
    }

    /* Try to return domain gid override. */
    if (domain->override_gid != 0) {
        return domain->override_gid;
    }

    /* Return original gid. */
    return ldb_msg_find_attr_as_uint64(msg, SYSDB_GIDNUM, 0);
}

static const char *
sss_nss_get_homedir_override(TALLOC_CTX *mem_ctx,
                             struct ldb_message *msg,
                             struct sss_nss_ctx *nctx,
                             struct sss_domain_info *dom,
                             struct sss_nss_homedir_ctx *homedir_ctx)
{
    const char *homedir;
    bool is_override = false;

    homedir = sss_view_ldb_msg_find_attr_as_string_ex(dom, msg, SYSDB_HOMEDIR,
                                                      NULL, &is_override);
    homedir_ctx->original = homedir;

    /* Check to see which homedir_prefix to use. */
    if (dom->homedir_substr != NULL) {
        homedir_ctx->config_homedir_substr = dom->homedir_substr;
    } else if (nctx->homedir_substr != NULL) {
        homedir_ctx->config_homedir_substr = nctx->homedir_substr;
    }

    /* Individual overrides have the highest priority, only templates will be
     * expanded and no further options will be evaluated. */
    if (is_override) {
        return expand_homedir_template(mem_ctx, homedir,
                                       dom->case_preserve, homedir_ctx);
    }

    /* Here we skip the files provider as it should always return *only*
     * what's in the files and nothing else.
     */
    if (!is_files_provider(dom)) {
        /* Check whether we are unconditionally overriding the server
         * for home directory locations.
         */
        if (dom->override_homedir) {
            return expand_homedir_template(mem_ctx, dom->override_homedir,
                                           dom->case_preserve, homedir_ctx);
        } else if (nctx->override_homedir) {
            return expand_homedir_template(mem_ctx, nctx->override_homedir,
                                           dom->case_preserve, homedir_ctx);
        }
    }

    if (!homedir || *homedir == '\0') {
        /* In the case of a NULL or empty homedir, check to see if
         * we have a fallback homedir to use.
         */
        if (dom->fallback_homedir) {
            return expand_homedir_template(mem_ctx, dom->fallback_homedir,
                                           dom->case_preserve, homedir_ctx);
        } else if (nctx->fallback_homedir) {
            return expand_homedir_template(mem_ctx, nctx->fallback_homedir,
                                           dom->case_preserve, homedir_ctx);
        }
    }

    /* Provider can also return template, try to expand it.*/
    return expand_homedir_template(mem_ctx, homedir,
                                   dom->case_preserve, homedir_ctx);
}

static const char *
sss_nss_get_homedir(TALLOC_CTX *mem_ctx,
                    struct sss_nss_ctx *nss_ctx,
                    struct sss_domain_info *domain,
                    struct ldb_message *msg,
                    const char *orig_name,
                    const char *upn,
                    uid_t uid)
{
    struct sss_nss_homedir_ctx hd_ctx = { 0 };
    const char *homedir;

    hd_ctx.username = orig_name;
    hd_ctx.uid = uid;
    hd_ctx.domain = domain->name;
    hd_ctx.upn = upn;
    hd_ctx.flatname = domain->flat_name;

    homedir = sss_nss_get_homedir_override(mem_ctx, msg, nss_ctx, domain, &hd_ctx);
    if (homedir == NULL) {
        return "";
    }

    return homedir;
}

static errno_t
sss_nss_get_shell(struct sss_nss_ctx *nss_ctx,
                  struct sss_domain_info *domain,
                  struct ldb_message *msg,
                  const char *name,
                  uint32_t uid,
                  const char **_shell)
{
    const char *shell = NULL;

    if (nss_ctx->rctx->sr_conf.scope != SESSION_RECORDING_SCOPE_NONE) {
        const char *sr_enabled;
        sr_enabled = ldb_msg_find_attr_as_string(
                                    msg, SYSDB_SESSION_RECORDING, NULL);
        if (sr_enabled == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "%s attribute not found for %s[%u]! Skipping\n",
                  SYSDB_SESSION_RECORDING, name, uid);
            return EINVAL;
        } else if (strcmp(sr_enabled, "TRUE") == 0) {
            shell = SESSION_RECORDING_SHELL;
        } else if (strcmp(sr_enabled, "FALSE") != 0) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Skipping %s[%u] "
                  "because its %s attribute value is invalid: %s\n",
                  name, uid, SYSDB_SESSION_RECORDING, sr_enabled);
            return EINVAL;
        }
    }
    if (shell == NULL) {
        shell = sss_resp_get_shell_override(msg, nss_ctx->rctx, domain);
    }

    *_shell = shell;
    return EOK;
}

static errno_t
sss_nss_get_pwent(TALLOC_CTX *mem_ctx,
                  struct sss_nss_ctx *nss_ctx,
                  struct sss_domain_info *domain,
                  struct ldb_message *msg,
                  uint32_t *_uid,
                  uint32_t *_gid,
                  struct sized_string **_name,
                  struct sized_string *_gecos,
                  struct sized_string *_homedir,
                  struct sized_string *_shell)
{
    const char *upn;
    const char *name;
    const char *gecos;
    const char *homedir;
    const char *shell;
    uint32_t gid;
    uint32_t uid;
    errno_t ret;

    /* Get fields. */
    upn = ldb_msg_find_attr_as_string(msg, SYSDB_UPN, NULL);
    name = sss_get_name_from_msg(domain, msg);
    gid = sss_nss_get_gid(domain, msg);
    uid = sss_view_ldb_msg_find_attr_as_uint64(domain, msg, SYSDB_UIDNUM, 0);

    if (name == NULL || uid == 0 || gid == 0) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Incomplete user object for %s[%u]! Skipping\n",
              name ? name : "<NULL>", uid);
        return EINVAL;
    }

    gecos = sss_view_ldb_msg_find_attr_as_string(domain, msg, SYSDB_GECOS,
                                                 NULL);
    homedir = sss_nss_get_homedir(mem_ctx, nss_ctx, domain, msg, name, upn, uid);
    ret = sss_nss_get_shell(nss_ctx, domain, msg, name, uid, &shell);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "failed retrieving shell for %s[%u], skipping [%d]: %s\n",
              name, uid, ret, sss_strerror(ret));
        return ret;
    }

    /* Convert to sized strings. */
    ret = sized_output_name(mem_ctx, nss_ctx->rctx, name, domain, _name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sized_output_name failed, skipping [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    to_sized_string(_gecos, gecos == NULL ? "" : gecos);
    to_sized_string(_shell, shell);
    to_sized_string(_homedir, homedir);

    *_gid = gid;
    *_uid = uid;

    return EOK;
}

errno_t
sss_nss_protocol_fill_pwent(struct sss_nss_ctx *nss_ctx,
                            struct sss_nss_cmd_ctx *cmd_ctx,
                            struct sss_packet *packet,
                            struct cache_req_result *result)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    struct sized_string pwfield;
    struct sized_string *name;
    struct sized_string gecos;
    struct sized_string homedir;
    struct sized_string shell;
    uint32_t gid;
    uint32_t uid;
    uint32_t num_results;
    size_t rp;
    size_t body_len;
    uint8_t *body;
    int i;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* First two fields (length and reserved), filled up later. */
    ret = sss_packet_grow(packet, 2 * sizeof(uint32_t));
    if (ret != EOK) {
        return ret;
    }

    rp = 2 * sizeof(uint32_t);

    num_results = 0;
    for (i = 0; i < result->count; i++) {
        talloc_free_children(tmp_ctx);
        msg = result->msgs[i];

        /* Password field content. */
        to_sized_string(&pwfield, sss_nss_get_pwfield(nss_ctx, result->domain));

        ret = sss_nss_get_pwent(tmp_ctx, nss_ctx, result->domain, msg, &uid, &gid,
                            &name, &gecos, &homedir, &shell);
        if (ret != EOK) {
            continue;
        }

        /* Adjust packet size: uid, gid + string fields. */

        ret = sss_packet_grow(packet, 2 * sizeof(uint32_t)
                                          + name->len + gecos.len + homedir.len
                                          + shell.len + pwfield.len);
        if (ret != EOK) {
            goto done;
        }

        sss_packet_get_body(packet, &body, &body_len);

        /* Fill packet. */

        SAFEALIGN_SET_UINT32(&body[rp], uid, &rp);
        SAFEALIGN_SET_UINT32(&body[rp], gid, &rp);
        SAFEALIGN_SET_STRING(&body[rp], name->str, name->len, &rp);
        SAFEALIGN_SET_STRING(&body[rp], pwfield.str, pwfield.len, &rp);
        SAFEALIGN_SET_STRING(&body[rp], gecos.str, gecos.len, &rp);
        SAFEALIGN_SET_STRING(&body[rp], homedir.str, homedir.len, &rp);
        SAFEALIGN_SET_STRING(&body[rp], shell.str, shell.len, &rp);

        num_results++;

        /* Do not store entry in memory cache during enumeration or when
         * requested or if cache explicitly disabled. */
        if (!cmd_ctx->enumeration
                && ((cmd_ctx->flags & SSS_NSS_EX_FLAG_INVALIDATE_CACHE) == 0)
                && (nss_ctx->pwd_mc_ctx != NULL)) {
            ret = sss_mmap_cache_pw_store(&nss_ctx->pwd_mc_ctx, name, &pwfield,
                                          uid, gid, &gecos, &homedir, &shell);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to store user %s (%s) in mmap cache [%d]: %s!\n",
                      name->str, result->domain->name, ret, sss_strerror(ret));
            }
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    if (ret != EOK) {
        sss_packet_set_size(packet, 0);
        return ret;
    }

    sss_packet_get_body(packet, &body, &body_len);
    SAFEALIGN_COPY_UINT32(body, &num_results, NULL);
    SAFEALIGN_SETMEM_UINT32(body + sizeof(uint32_t), 0, NULL); /* reserved */

    return EOK;
}
