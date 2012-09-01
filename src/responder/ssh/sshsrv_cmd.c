/*
    Authors:
        Jan Cholasta <jcholast@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include "config.h"

#include <talloc.h>
#include <string.h>
#include <netdb.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "util/sss_ssh.h"
#include "db/sysdb.h"
#include "db/sysdb_ssh.h"
#include "providers/data_provider.h"
#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"
#include "responder/ssh/sshsrv_private.h"

static errno_t
ssh_cmd_parse_request(struct ssh_cmd_ctx *cmd_ctx);

static errno_t
ssh_cmd_done(struct ssh_cmd_ctx *cmd_ctx,
             errno_t ret);

static errno_t
ssh_user_pubkeys_search(struct ssh_cmd_ctx *cmd_ctx);

int
sss_ssh_cmd_get_user_pubkeys(struct cli_ctx *cctx)
{
    errno_t ret;
    struct ssh_cmd_ctx *cmd_ctx;

    cmd_ctx = talloc_zero(cctx, struct ssh_cmd_ctx);
    if (!cmd_ctx) {
        return ENOMEM;
    }
    cmd_ctx->cctx = cctx;

    ret = ssh_cmd_parse_request(cmd_ctx);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Requesting SSH user public keys for [%s] from [%s]\n",
           cmd_ctx->name, cmd_ctx->domname ? cmd_ctx->domname : "<ALL>"));

    if (cmd_ctx->domname) {
        cmd_ctx->domain = responder_get_domain(cmd_ctx, cctx->rctx,
                                               cmd_ctx->domname);
        if (!cmd_ctx->domain) {
            ret = ENOENT;
            goto done;
        }
    } else {
        cmd_ctx->domain = cctx->rctx->domains;
        cmd_ctx->check_next = true;
    }

    ret = ssh_user_pubkeys_search(cmd_ctx);

done:
    return ssh_cmd_done(cmd_ctx, ret);
}

static errno_t
ssh_host_pubkeys_search(struct ssh_cmd_ctx *cmd_ctx);

static int
sss_ssh_cmd_get_host_pubkeys(struct cli_ctx *cctx)
{
    errno_t ret;
    struct ssh_cmd_ctx *cmd_ctx;

    cmd_ctx = talloc_zero(cctx, struct ssh_cmd_ctx);
    if (!cmd_ctx) {
        return ENOMEM;
    }
    cmd_ctx->cctx = cctx;

    ret = ssh_cmd_parse_request(cmd_ctx);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Requesting SSH host public keys for [%s][%s] from [%s]\n",
           cmd_ctx->name, cmd_ctx->alias ? cmd_ctx->alias : "",
           cmd_ctx->domname ? cmd_ctx->domname : "<ALL>"));

    if (cmd_ctx->domname) {
        cmd_ctx->domain = responder_get_domain(cmd_ctx, cctx->rctx,
                                               cmd_ctx->domname);
        if (!cmd_ctx->domain) {
            ret = ENOENT;
            goto done;
        }
    } else {
        cmd_ctx->domain = cctx->rctx->domains;
        cmd_ctx->check_next = true;
    }

    ret = ssh_host_pubkeys_search(cmd_ctx);

done:
    return ssh_cmd_done(cmd_ctx, ret);
}

static void
ssh_dp_send_req_done(struct tevent_req *req)
{
    struct dp_callback_ctx *cb_ctx =
            tevent_req_callback_data(req, struct dp_callback_ctx);

    errno_t ret;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    char *err_msg;

    ret = sss_dp_get_ssh_host_recv(cb_ctx->mem_ctx, req,
                                   &err_maj, &err_min,
                                   &err_msg);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Fatal error, killing connection!\n"));
        talloc_free(cb_ctx->cctx);
        return;
    }

    cb_ctx->callback(err_maj, err_min, err_msg, cb_ctx->ptr);
}

static errno_t
ssh_user_pubkeys_search_next(struct ssh_cmd_ctx *cmd_ctx);
static void
ssh_user_pubkeys_search_dp_callback(uint16_t err_maj,
                                    uint32_t err_min,
                                    const char *err_msg,
                                    void *ptr);

static errno_t
ssh_user_pubkeys_search(struct ssh_cmd_ctx *cmd_ctx)
{
    struct tevent_req *req;
    struct dp_callback_ctx *cb_ctx;

    /* if it is a domainless search, skip domains that require fully
     * qualified names instead */
    while (cmd_ctx->domain && cmd_ctx->check_next && cmd_ctx->domain->fqnames) {
        cmd_ctx->domain = cmd_ctx->domain->next;
    }

    if (!cmd_ctx->domain) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("No matching domain found for [%s], fail!\n", cmd_ctx->name));
        return ENOENT;
    }

    /* refresh the user's cache entry */
    if (NEED_CHECK_PROVIDER(cmd_ctx->domain->provider)) {
        req = sss_dp_get_account_send(cmd_ctx, cmd_ctx->cctx->rctx,
                                      cmd_ctx->domain, false, SSS_DP_USER,
                                      cmd_ctx->name, 0, NULL);
        if (!req) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Out of memory sending data provider request\n"));
            return ENOMEM;
        }

        cb_ctx = talloc_zero(cmd_ctx, struct dp_callback_ctx);
        if (!cb_ctx) {
            talloc_zfree(req);
            return ENOMEM;
        }

        cb_ctx->callback = ssh_user_pubkeys_search_dp_callback;
        cb_ctx->ptr = cmd_ctx;
        cb_ctx->cctx = cmd_ctx->cctx;
        cb_ctx->mem_ctx = cmd_ctx;

        tevent_req_set_callback(req, ssh_dp_send_req_done, cb_ctx);

        /* tell caller we are in an async call */
        return EAGAIN;
    }

    return ssh_user_pubkeys_search_next(cmd_ctx);
}

static errno_t
ssh_user_pubkeys_search_next(struct ssh_cmd_ctx *cmd_ctx)
{
    errno_t ret;
    struct sysdb_ctx *sysdb;
    const char *attrs[] = { SYSDB_NAME, SYSDB_SSH_PUBKEY, NULL };
    struct ldb_result *res;

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Requesting SSH user public keys for [%s@%s]\n",
           cmd_ctx->name, cmd_ctx->domain->name));

    sysdb = cmd_ctx->domain->sysdb;
    if (sysdb == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Fatal: Sysdb CTX not found for this domain!\n"));
        return EFAULT;
    }

    ret = sysdb_get_user_attr(cmd_ctx, sysdb,
                              cmd_ctx->name, attrs, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Failed to make request to our cache!\n"));
        return EIO;
    }

    cmd_ctx->results = res->msgs;
    cmd_ctx->results_len = res->count;

    if (cmd_ctx->results_len > 1) {
        DEBUG(SSSDBG_FATAL_FAILURE,
            ("User search by name (%s) returned > 1 results!\n",
             cmd_ctx->name));
        return ENOENT;
    }

    if (cmd_ctx->results_len == 0) {
        /* if a multidomain search, try with next */
        if (cmd_ctx->check_next) {
            cmd_ctx->domain = cmd_ctx->domain->next;
            return ssh_user_pubkeys_search(cmd_ctx);
        }

        DEBUG(SSSDBG_OP_FAILURE,
              ("No attributes for user [%s] found.\n", cmd_ctx->name));

        return ENOENT;
    }

    /* one result found */
    return EOK;
}

static void
ssh_user_pubkeys_search_dp_callback(uint16_t err_maj,
                                    uint32_t err_min,
                                    const char *err_msg,
                                    void *ptr)
{
    struct ssh_cmd_ctx *cmd_ctx = talloc_get_type(ptr, struct ssh_cmd_ctx);
    errno_t ret;

    if (err_maj) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Unable to get information from Data Provider\n"
               "Error: %u, %u, %s\n",
               (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    ret = ssh_user_pubkeys_search_next(cmd_ctx);
    ssh_cmd_done(cmd_ctx, ret);
}

static errno_t
ssh_host_pubkeys_search_next(struct ssh_cmd_ctx *cmd_ctx);
static void
ssh_host_pubkeys_search_dp_callback(uint16_t err_maj,
                                    uint32_t err_min,
                                    const char *err_msg,
                                    void *ptr);

static errno_t
ssh_host_pubkeys_search(struct ssh_cmd_ctx *cmd_ctx)
{
    struct tevent_req *req;
    struct dp_callback_ctx *cb_ctx;

    /* if it is a domainless search, skip domains that require fully
     * qualified names instead */
    while (cmd_ctx->domain && cmd_ctx->check_next && cmd_ctx->domain->fqnames) {
        cmd_ctx->domain = cmd_ctx->domain->next;
    }

    if (!cmd_ctx->domain) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("No matching domain found for [%s], fail!\n", cmd_ctx->name));
        return ENOENT;
    }

    /* refresh the host's cache entry */
    if (NEED_CHECK_PROVIDER(cmd_ctx->domain->provider)) {
        req = sss_dp_get_ssh_host_send(cmd_ctx, cmd_ctx->cctx->rctx,
                                       cmd_ctx->domain, false,
                                       cmd_ctx->name, cmd_ctx->alias);
        if (!req) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  ("Out of memory sending data provider request\n"));
            return ENOMEM;
        }

        cb_ctx = talloc_zero(cmd_ctx, struct dp_callback_ctx);
        if (!cb_ctx) {
            talloc_zfree(req);
            return ENOMEM;
        }

        cb_ctx->callback = ssh_host_pubkeys_search_dp_callback;
        cb_ctx->ptr = cmd_ctx;
        cb_ctx->cctx = cmd_ctx->cctx;
        cb_ctx->mem_ctx = cmd_ctx;

        tevent_req_set_callback(req, ssh_dp_send_req_done, cb_ctx);

        /* tell caller we are in an async call */
        return EAGAIN;
    }

    return ssh_host_pubkeys_search_next(cmd_ctx);
}

static errno_t
ssh_host_pubkeys_update_known_hosts(struct ssh_cmd_ctx *cmd_ctx);

static errno_t
ssh_host_pubkeys_search_next(struct ssh_cmd_ctx *cmd_ctx)
{
    errno_t ret;
    struct sysdb_ctx *sysdb;
    const char *attrs[] = { SYSDB_NAME, SYSDB_SSH_PUBKEY, NULL };

    DEBUG(SSSDBG_TRACE_FUNC,
          ("Requesting SSH host public keys for [%s@%s]\n",
           cmd_ctx->name, cmd_ctx->domain->name));

    sysdb = cmd_ctx->domain->sysdb;
    if (sysdb == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              ("Fatal: Sysdb CTX not found for this domain!\n"));
        return EFAULT;
    }

    ret = sysdb_search_ssh_hosts(cmd_ctx, sysdb,
                                 cmd_ctx->name, attrs,
                                 &cmd_ctx->results, &cmd_ctx->results_len);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Failed to make request to our cache!\n"));
        return EIO;
    }

    if (cmd_ctx->results_len > 1) {
        DEBUG(SSSDBG_FATAL_FAILURE,
            ("Host search by name (%s) returned > 1 results!\n",
             cmd_ctx->name));
        return ENOENT;
    }

    if (cmd_ctx->results_len == 0) {
        /* if a multidomain search, try with next */
        if (cmd_ctx->check_next) {
            cmd_ctx->domain = cmd_ctx->domain->next;
            return ssh_host_pubkeys_search(cmd_ctx);
        }

        DEBUG(SSSDBG_OP_FAILURE,
              ("No attributes for host [%s] found.\n", cmd_ctx->name));

        return ENOENT;
    }

    /* one result found */
    ssh_host_pubkeys_update_known_hosts(cmd_ctx);

    return EOK;
}

static void
ssh_host_pubkeys_search_dp_callback(uint16_t err_maj,
                                    uint32_t err_min,
                                    const char *err_msg,
                                    void *ptr)
{
    struct ssh_cmd_ctx *cmd_ctx = talloc_get_type(ptr, struct ssh_cmd_ctx);
    errno_t ret;

    if (err_maj) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Unable to get information from Data Provider\n"
               "Error: %u, %u, %s\n",
               (unsigned int)err_maj, (unsigned int)err_min, err_msg));
    }

    ret = ssh_host_pubkeys_search_next(cmd_ctx);
    ssh_cmd_done(cmd_ctx, ret);
}

static char *
ssh_host_pubkeys_format_known_host_plain(TALLOC_CTX *mem_ctx,
                                         struct sss_ssh_ent *ent)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    char *name, *pubkey;
    char *result = NULL;
    size_t i;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return NULL;
    }

    name = talloc_strdup(tmp_ctx, ent->name);
    if (!name) {
        goto done;
    }

    for (i = 0; i < ent->num_aliases; i++) {
        name = talloc_asprintf_append(name, ",%s", ent->aliases[i]);
        if (!name) {
            goto done;
        }
    }

    result = talloc_strdup(tmp_ctx, "");
    if (!result) {
        goto done;
    }

    for (i = 0; i < ent->num_pubkeys; i++) {
        ret = sss_ssh_format_pubkey(tmp_ctx, &ent->pubkeys[i], &pubkey);
        if (ret != EOK) {
            result = NULL;
            goto done;
        }

        result = talloc_asprintf_append(result, "%s %s\n", name, pubkey);
        if (!result) {
            goto done;
        }

        talloc_free(pubkey);
    }

    talloc_steal(mem_ctx, result);

done:
    talloc_free(tmp_ctx);

    return result;
}

static char *
ssh_host_pubkeys_format_known_host_hashed(TALLOC_CTX *mem_ctx,
                                          struct sss_ssh_ent *ent)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    char *name, *pubkey, *saltstr, *hashstr, *result;
    unsigned char salt[SSS_SHA1_LENGTH], hash[SSS_SHA1_LENGTH];
    size_t i, j, k;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return NULL;
    }

    result = talloc_strdup(tmp_ctx, "");
    if (!result) {
        goto done;
    }

    for (i = 0; i < ent->num_pubkeys; i++) {
        ret = sss_ssh_format_pubkey(tmp_ctx, &ent->pubkeys[i], &pubkey);
        if (ret != EOK) {
            result = NULL;
            goto done;
        }

        for (j = 0; j <= ent->num_aliases; j++) {
            name = (j == 0 ? ent->name : ent->aliases[j-1]);

            for (k = 0; k < SSS_SHA1_LENGTH; k++) {
                salt[k] = rand();
            }

            ret = sss_hmac_sha1(salt, SSS_SHA1_LENGTH,
                                (unsigned char *)name, strlen(name),
                                hash);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      ("sss_hmac_sha1() failed (%d): %s\n",
                       ret, strerror(ret)));
                result = NULL;
                goto done;
            }

            saltstr = sss_base64_encode(tmp_ctx, salt, SSS_SHA1_LENGTH);
            if (!saltstr) {
                result = NULL;
                goto done;
            }

            hashstr = sss_base64_encode(tmp_ctx, hash, SSS_SHA1_LENGTH);
            if (!hashstr) {
                result = NULL;
                goto done;
            }

            result = talloc_asprintf_append(result, "|1|%s|%s %s\n",
                                            saltstr, hashstr, pubkey);
            if (!result) {
                goto done;
            }

            talloc_free(saltstr);
            talloc_free(hashstr);
        }

        talloc_free(pubkey);
    }

    talloc_steal(mem_ctx, result);

done:
    talloc_free(tmp_ctx);

    return result;
}

static errno_t
ssh_host_pubkeys_update_known_hosts(struct ssh_cmd_ctx *cmd_ctx)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    const char *attrs[] = {
        SYSDB_NAME,
        SYSDB_NAME_ALIAS,
        SYSDB_SSH_PUBKEY,
        NULL
    };
    struct cli_ctx *cctx = cmd_ctx->cctx;
    struct sss_domain_info *dom = cctx->rctx->domains;
    struct ssh_ctx *ssh_ctx = (struct ssh_ctx *)cctx->rctx->pvt_ctx;
    struct sysdb_ctx *sysdb;
    struct ldb_message **hosts;
    size_t num_hosts, i;
    struct sss_ssh_ent *ent;
    int fd = -1;
    char *filename, *entstr;
    ssize_t wret;
    mode_t old_mask;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    /* write known_hosts file */
    filename = talloc_strdup(tmp_ctx, SSS_SSH_KNOWN_HOSTS_TEMP_TMPL);
    if (!filename) {
        ret = ENOMEM;
        goto done;
    }

    old_mask = umask(0133);
    fd = mkstemp(filename);
    umask(old_mask);
    if (fd == -1) {
        filename = NULL;
        ret = errno;
        goto done;
    }

    while (dom) {
        sysdb = dom->sysdb;
        if (sysdb == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  ("Fatal: Sysdb CTX not found for this domain!\n"));
            ret = EFAULT;
            goto done;
        }

        ret = sysdb_search_ssh_hosts(tmp_ctx, sysdb, "*", attrs,
                                     &hosts, &num_hosts);
        if (ret != EOK) {
            if (ret != ENOENT) {
                DEBUG(SSSDBG_OP_FAILURE,
                      ("Host search failed for domain [%s]\n", dom->name));
            }
            continue;
        }

        for (i = 0; i < num_hosts; i++) {
            ret = sss_ssh_make_ent(tmp_ctx, hosts[i], &ent);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      ("Failed to get SSH host public keys\n"));
                continue;
            }

            if (ssh_ctx->hash_known_hosts) {
                entstr = ssh_host_pubkeys_format_known_host_hashed(ent, ent);
            } else {
                entstr = ssh_host_pubkeys_format_known_host_plain(ent, ent);
            }
            if (!entstr) {
                DEBUG(SSSDBG_OP_FAILURE,
                      ("Failed to format known_hosts data for [%s]\n",
                       ent->name));
                continue;
            }

            wret = sss_atomic_write_s(fd, entstr, strlen(entstr));
            if (wret == -1) {
                ret = errno;
                goto done;
            }

            talloc_free(ent);
        }

        talloc_free(hosts);

        dom = dom->next;
    }

    ret = fchmod(fd, 0644);
    if (ret == -1) {
        ret = errno;
        goto done;
    }

    ret = rename(filename, SSS_SSH_KNOWN_HOSTS_PATH);
    if (ret == -1) {
        ret = errno;
        goto done;
    }

    ret = EOK;

done:
    if (fd != -1) close(fd);
    if (ret != EOK && filename) unlink(filename);
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t
ssh_cmd_parse_request(struct ssh_cmd_ctx *cmd_ctx)
{
    struct cli_ctx *cctx = cmd_ctx->cctx;
    errno_t ret;
    uint8_t *body;
    size_t body_len;
    size_t c = 0;
    uint32_t flags;
    uint32_t name_len;
    char *name;
    uint32_t alias_len;
    char *alias;

    sss_packet_get_body(cctx->creq->in, &body, &body_len);

    SAFEALIGN_COPY_UINT32_CHECK(&flags, body+c, body_len, &c);
    if (flags > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Invalid flags received [0x%x]\n", flags));
        return EINVAL;
    }

    SAFEALIGN_COPY_UINT32_CHECK(&name_len, body+c, body_len, &c);
    if (name_len == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Zero-length name is not valid\n"));
        return EINVAL;
    }

    name = (char *)(body+c);
    if (!sss_utf8_check((const uint8_t *)name, name_len-1) ||
            name[name_len-1] != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Name is not valid UTF-8 string\n"));
        return EINVAL;
    }
    c += name_len;

    ret = sss_parse_name_for_domains(cmd_ctx, cctx->rctx->domains, name,
                                     &cmd_ctx->domname, &cmd_ctx->name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Invalid name received [%s]\n", name));
        return ENOENT;
    }

    if (flags & 1) {
        SAFEALIGN_COPY_UINT32_CHECK(&alias_len, body+c, body_len, &c);
        if (alias_len == 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Zero-length alias is not valid\n"));
            return EINVAL;
        }

        alias = (char *)(body+c);
        if (!sss_utf8_check((const uint8_t *)alias, alias_len-1) ||
                alias[alias_len-1] != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Alias is not valid UTF-8 string\n"));
            return EINVAL;
        }
        c += alias_len;

        if (strcmp(cmd_ctx->name, alias) != 0) {
            cmd_ctx->alias = talloc_strdup(cmd_ctx, alias);
            if (!cmd_ctx->alias) return ENOMEM;
        }
    }

    return EOK;
}

static errno_t
ssh_cmd_build_reply(struct ssh_cmd_ctx *cmd_ctx)
{
    struct cli_ctx *cctx = cmd_ctx->cctx;
    errno_t ret;
    uint8_t *body;
    size_t body_len;
    size_t c = 0;
    size_t i;
    unsigned int j;
    struct ldb_message_element *el;
    uint32_t count = 0;
    const char *name;
    char *fqname;
    uint32_t fqname_len;
    uint8_t *key;
    size_t key_len;

    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    /* count number of results */
    for (i = 0; i < cmd_ctx->results_len; i++) {
        el = ldb_msg_find_element(cmd_ctx->results[i], SYSDB_SSH_PUBKEY);
        if (!el) {
            continue;
        }

        count += el->num_values;
    }

    ret = sss_packet_grow(cctx->creq->out, 2*sizeof(uint32_t));
    if (ret != EOK) {
        return ret;
    }
    sss_packet_get_body(cctx->creq->out, &body, &body_len);

    SAFEALIGN_SET_UINT32(body+c, count, &c);
    SAFEALIGN_SET_UINT32(body+c, 0, &c);

    for (i = 0; i < cmd_ctx->results_len; i++) {
        name = ldb_msg_find_attr_as_string(cmd_ctx->results[i],
                                           SYSDB_NAME, NULL);
        if (!name) {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Got unnamed result for [%s@%s]\n",
                   cmd_ctx->name, cmd_ctx->domain->name));
            return ENOENT;
        }

        fqname = talloc_asprintf(cmd_ctx, "%s@%s",
                                 name, cmd_ctx->domain->name);
        if (!fqname) {
            return ENOMEM;
        }

        fqname_len = strlen(fqname)+1;

        el = ldb_msg_find_element(cmd_ctx->results[i], SYSDB_SSH_PUBKEY);
        if (!el) {
            /* this object has no SSH public keys */
            continue;
        }

        for (j = 0; j < el->num_values; j++) {
            key = sss_base64_decode(cmd_ctx,
                                    (const char *)el->values[j].data,
                                    &key_len);
            if (!key) {
                return ENOMEM;
            }

            ret = sss_packet_grow(cctx->creq->out,
                                  3*sizeof(uint32_t) + key_len + fqname_len);
            if (ret != EOK) {
                talloc_free(key);
                return ret;
            }
            sss_packet_get_body(cctx->creq->out, &body, &body_len);

            SAFEALIGN_SET_UINT32(body+c, 0, &c);
            SAFEALIGN_SET_UINT32(body+c, fqname_len, &c);
            safealign_memcpy(body+c, fqname, fqname_len, &c);
            SAFEALIGN_SET_UINT32(body+c, key_len, &c);
            safealign_memcpy(body+c, key, key_len, &c);

            talloc_free(key);
            count++;
        }
    }

    return EOK;
}

static errno_t
ssh_cmd_send_error(struct ssh_cmd_ctx *cmd_ctx,
                   errno_t error)
{
    struct cli_ctx *cctx = cmd_ctx->cctx;
    errno_t ret;

    ret = sss_cmd_send_error(cctx, error);
    if (ret != EOK) {
        return ret;
    }

    sss_cmd_done(cctx, cmd_ctx);

    return EOK;
}

static errno_t
ssh_cmd_send_reply(struct ssh_cmd_ctx *cmd_ctx)
{
    struct cli_ctx *cctx = cmd_ctx->cctx;
    errno_t ret;

    /* create response packet */
    ret = ssh_cmd_build_reply(cmd_ctx);
    if (ret != EOK) {
        return ret;
    }

    sss_packet_set_error(cctx->creq->out, EOK);
    sss_cmd_done(cctx, cmd_ctx);

    return EOK;
}

static errno_t
ssh_cmd_done(struct ssh_cmd_ctx *cmd_ctx,
             errno_t ret)
{
    switch (ret) {
    case EOK:
        ret = ssh_cmd_send_reply(cmd_ctx);
        break;

    case EAGAIN:
        return EOK;

    case EFAULT:
        break;

    default:
        ret = ssh_cmd_send_error(cmd_ctx, ret);
        break;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Fatal error, killing connection!\n"));
        talloc_free(cmd_ctx->cctx);
        return EFAULT;
    }

    return EOK;
}

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version ssh_cli_protocol_version[] = {
        {0, NULL, NULL}
    };

    return ssh_cli_protocol_version;
}

struct sss_cmd_table *get_ssh_cmds(void) {
    static struct sss_cmd_table ssh_cmds[] = {
        {SSS_GET_VERSION, sss_cmd_get_version},
        {SSS_SSH_GET_USER_PUBKEYS, sss_ssh_cmd_get_user_pubkeys},
        {SSS_SSH_GET_HOST_PUBKEYS, sss_ssh_cmd_get_host_pubkeys},
        {SSS_CLI_NULL, NULL}
    };

    return ssh_cmds;
}
