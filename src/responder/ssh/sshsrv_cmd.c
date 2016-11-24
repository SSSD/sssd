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
#include "util/cert.h"
#include "db/sysdb.h"
#include "db/sysdb_ssh.h"
#include "providers/data_provider.h"
#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"
#include "responder/ssh/sshsrv_private.h"

static errno_t
ssh_cmd_parse_request(struct ssh_cmd_ctx *cmd_ctx,
                      char *default_domain);

static errno_t
ssh_user_pubkeys_search(struct ssh_cmd_ctx *cmd_ctx);
static errno_t
ssh_cmd_get_user_pubkeys_done(struct ssh_cmd_ctx *cmd_ctx,
                              errno_t ret);

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
    cmd_ctx->is_user = true;

    ret = ssh_cmd_parse_request(cmd_ctx, cctx->rctx->default_domain);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Requesting SSH user public keys for [%s] from [%s]\n",
           cmd_ctx->name, cmd_ctx->domname ? cmd_ctx->domname : "<ALL>");

    if (strcmp(cmd_ctx->name, "root") == 0) {
        ret = ERR_NON_SSSD_USER;
        goto done;
    }

    if (cmd_ctx->domname) {
        cmd_ctx->domain = responder_get_domain(cctx->rctx, cmd_ctx->domname);
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
    return ssh_cmd_get_user_pubkeys_done(cmd_ctx, ret);
}

static errno_t
ssh_host_pubkeys_search(struct ssh_cmd_ctx *cmd_ctx);
static errno_t
ssh_cmd_get_host_pubkeys_done(struct ssh_cmd_ctx *cmd_ctx,
                              errno_t ret);

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
    cmd_ctx->is_user = false;

    ret = ssh_cmd_parse_request(cmd_ctx, NULL);
    if (ret != EOK) {
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Requesting SSH host public keys for [%s][%s] from [%s]\n",
           cmd_ctx->name, cmd_ctx->alias ? cmd_ctx->alias : "",
           cmd_ctx->domname ? cmd_ctx->domname : "<ALL>");

    if (cmd_ctx->domname) {
        cmd_ctx->domain = responder_get_domain(cctx->rctx, cmd_ctx->domname);
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
    return ssh_cmd_get_host_pubkeys_done(cmd_ctx, ret);
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
              "Fatal error, killing connection!\n");
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
ssh_user_handle_not_found(const char *username)
{
    struct passwd *pwd;

    pwd = getpwnam(username);
    if (pwd != NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "%s is a non-SSSD user\n", username);
        return ERR_NON_SSSD_USER;
    }

    return ENOENT;
}

static errno_t
ssh_user_pubkeys_search(struct ssh_cmd_ctx *cmd_ctx)
{
    struct tevent_req *req;
    struct dp_callback_ctx *cb_ctx;

    /* if it is a domainless search, skip domains that require fully
     * qualified names instead */
    while (cmd_ctx->domain && cmd_ctx->check_next && cmd_ctx->domain->fqnames) {
        cmd_ctx->domain = get_next_domain(cmd_ctx->domain, false);
    }

    if (!cmd_ctx->domain) {
        DEBUG(SSSDBG_OP_FAILURE,
              "No matching domain found for [%s], fail!\n", cmd_ctx->name);
        return ssh_user_handle_not_found(cmd_ctx->name);
    }

    talloc_zfree(cmd_ctx->fqdn);
    cmd_ctx->fqdn = sss_resp_create_fqname(cmd_ctx, cmd_ctx->cctx->rctx,
                                           cmd_ctx->domain, false, cmd_ctx->name);
    if (cmd_ctx->fqdn == NULL) {
        return ENOMEM;
    }

    /* refresh the user's cache entry */
    if (NEED_CHECK_PROVIDER(cmd_ctx->domain->provider)) {
        req = sss_dp_get_account_send(cmd_ctx, cmd_ctx->cctx->rctx,
                                      cmd_ctx->domain, false, SSS_DP_USER,
                                      cmd_ctx->fqdn, 0, NULL);
        if (!req) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Out of memory sending data provider request\n");
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
    const char *attrs[] = { SYSDB_NAME, SYSDB_SSH_PUBKEY, SYSDB_USER_CERT,
                            NULL };
    struct ldb_result *res;

    DEBUG(SSSDBG_TRACE_FUNC,
          "Requesting SSH user public keys for [%s@%s]\n",
           cmd_ctx->name, cmd_ctx->domain->name);

    if (cmd_ctx->domain->sysdb == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Fatal: Sysdb CTX not found for this domain!\n");
        return EFAULT;
    }

    ret = sysdb_get_user_attr_with_views(cmd_ctx, cmd_ctx->domain,
                                         cmd_ctx->fqdn, attrs, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to make request to our cache!\n");
        return EIO;
    }

    if (res->count > 1) {
        DEBUG(SSSDBG_FATAL_FAILURE,
            "User search by name (%s) returned > 1 results!\n",
             cmd_ctx->name);
        return EINVAL;
    }

    if (!res->count) {
        /* if a multidomain search, try with next */
        if (cmd_ctx->check_next) {
            cmd_ctx->domain = get_next_domain(cmd_ctx->domain, false);
            return ssh_user_pubkeys_search(cmd_ctx);
        }

        DEBUG(SSSDBG_MINOR_FAILURE,
              "No attributes for user [%s] found.\n", cmd_ctx->name);

        return ssh_user_handle_not_found(cmd_ctx->name);
    }

    cmd_ctx->result = res->msgs[0];

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
              "Unable to get information from Data Provider\n"
               "Error: %u, %u, %s\n",
               (unsigned int)err_maj, (unsigned int)err_min, err_msg);
    }

    ret = ssh_user_pubkeys_search_next(cmd_ctx);
    ssh_cmd_get_user_pubkeys_done(cmd_ctx, ret);
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

    if (!cmd_ctx->domain) {
        DEBUG(SSSDBG_OP_FAILURE,
              "No matching domain found for [%s], fail!\n", cmd_ctx->name);
        return ENOENT;
    }

    /* refresh the host's cache entry */
    if (NEED_CHECK_PROVIDER(cmd_ctx->domain->provider)) {
        req = sss_dp_get_ssh_host_send(cmd_ctx, cmd_ctx->cctx->rctx,
                                       cmd_ctx->domain, false,
                                       cmd_ctx->name, cmd_ctx->alias);
        if (!req) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Out of memory sending data provider request\n");
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
ssh_host_pubkeys_search_next(struct ssh_cmd_ctx *cmd_ctx)
{
    errno_t ret;
    struct sysdb_ctx *sysdb;
    const char *attrs[] = { SYSDB_NAME, SYSDB_SSH_PUBKEY, NULL };

    DEBUG(SSSDBG_TRACE_FUNC,
          "Requesting SSH host public keys for [%s@%s]\n",
           cmd_ctx->name, cmd_ctx->domain->name);

    sysdb = cmd_ctx->domain->sysdb;
    if (sysdb == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Fatal: Sysdb CTX not found for this domain!\n");
        return EFAULT;
    }

    ret = sysdb_get_ssh_host(cmd_ctx, cmd_ctx->domain,
                             cmd_ctx->name, attrs, &cmd_ctx->result);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to make request to our cache!\n");
        return EIO;
    }

    if (ret == ENOENT) {
        /* if a multidomain search, try with next */
        if (cmd_ctx->check_next) {
            cmd_ctx->domain = get_next_domain(cmd_ctx->domain, false);
            return ssh_host_pubkeys_search(cmd_ctx);
        }

        DEBUG(SSSDBG_OP_FAILURE,
              "No attributes for host [%s] found.\n", cmd_ctx->name);

        return ENOENT;
    }

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
              "Unable to get information from Data Provider\n"
               "Error: %u, %u, %s\n",
               (unsigned int)err_maj, (unsigned int)err_min, err_msg);
    }

    ret = ssh_host_pubkeys_search_next(cmd_ctx);
    ssh_cmd_get_host_pubkeys_done(cmd_ctx, ret);
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
                      "sss_hmac_sha1() failed (%d): %s\n",
                       ret, strerror(ret));
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
    time_t now = time(NULL);
    struct ldb_message **hosts;
    size_t num_hosts, i;
    struct sss_ssh_ent *ent;
    int fd = -1;
    char *filename = NULL;
    char *entstr;
    ssize_t wret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (cmd_ctx->domain) {
        ret = sysdb_update_ssh_known_host_expire(cmd_ctx->domain,
                                                 cmd_ctx->name, now,
                                                 ssh_ctx->known_hosts_timeout);
        if (ret != EOK && ret != ENOENT) {
            goto done;
        }
    }

    /* write known_hosts file */
    filename = talloc_strdup(tmp_ctx, SSS_SSH_KNOWN_HOSTS_TEMP_TMPL);
    if (!filename) {
        ret = ENOMEM;
        goto done;
    }

    fd = sss_unique_file_ex(tmp_ctx, filename, 0133, &ret);
    if (fd == -1) {
        filename = NULL;
        goto done;
    }

    for (; dom; dom = get_next_domain(dom, false)) {
        sysdb = dom->sysdb;
        if (sysdb == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Fatal: Sysdb CTX not found for this domain!\n");
            ret = EFAULT;
            goto done;
        }

        ret = sysdb_get_ssh_known_hosts(tmp_ctx, dom, now, attrs,
                                        &hosts, &num_hosts);
        if (ret != EOK) {
            if (ret != ENOENT) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Host search failed for domain [%s]\n", dom->name);
            }
            continue;
        }

        for (i = 0; i < num_hosts; i++) {
            ret = sss_ssh_make_ent(tmp_ctx, hosts[i], &ent);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to get SSH host public keys\n");
                continue;
            }

            if (ssh_ctx->hash_known_hosts) {
                entstr = ssh_host_pubkeys_format_known_host_hashed(ent, ent);
            } else {
                entstr = ssh_host_pubkeys_format_known_host_plain(ent, ent);
            }
            if (!entstr) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to format known_hosts data for [%s]\n",
                       ent->name);
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
    if (fd != -1) {
        close(fd);
    }
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t
ssh_cmd_parse_request(struct ssh_cmd_ctx *cmd_ctx,
                      char *default_domain)
{
    struct cli_protocol *pctx;
    struct ssh_ctx *ssh_ctx;
    errno_t ret;
    uint8_t *body;
    size_t body_len;
    size_t c = 0;
    uint32_t flags;
    uint32_t name_len;
    char *name;
    uint32_t alias_len;
    char *alias = NULL;
    uint32_t domain_len;
    char *domain = NULL;

    ssh_ctx = talloc_get_type(cmd_ctx->cctx->rctx->pvt_ctx, struct ssh_ctx);
    pctx = talloc_get_type(cmd_ctx->cctx->protocol_ctx, struct cli_protocol);

    sss_packet_get_body(pctx->creq->in, &body, &body_len);

    SAFEALIGN_COPY_UINT32_CHECK(&flags, body+c, body_len, &c);
    if (flags & ~(uint32_t)SSS_SSH_REQ_MASK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid flags received [0x%x]\n", flags);
        return EINVAL;
    }

    SAFEALIGN_COPY_UINT32_CHECK(&name_len, body+c, body_len, &c);
    if (name_len == 0 || name_len > body_len - c) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid name length\n");
        return EINVAL;
    }

    name = (char *)(body+c);
    if (!sss_utf8_check((const uint8_t *)name, name_len-1) ||
            name[name_len-1] != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Name is not valid UTF-8 string\n");
        return EINVAL;
    }
    c += name_len;

    if (flags & SSS_SSH_REQ_ALIAS) {
        SAFEALIGN_COPY_UINT32_CHECK(&alias_len, body+c, body_len, &c);
        if (alias_len == 0 || alias_len > body_len - c) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Invalid alias length\n");
            return EINVAL;
        }

        alias = (char *)(body+c);
        if (!sss_utf8_check((const uint8_t *)alias, alias_len-1) ||
                alias[alias_len-1] != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Alias is not valid UTF-8 string\n");
            return EINVAL;
        }
        c += alias_len;
    }

    if (flags & SSS_SSH_REQ_DOMAIN) {
        SAFEALIGN_COPY_UINT32_CHECK(&domain_len, body+c, body_len, &c);
        if (domain_len > 0) {
            if (domain_len > body_len - c) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Invalid domain length\n");
                return EINVAL;
            }

            domain = (char *)(body+c);
            if (!sss_utf8_check((const uint8_t *)domain, domain_len-1) ||
                    domain[domain_len-1] != 0) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Domain is not valid UTF-8 string\n");
                return EINVAL;
            }
            c += domain_len;
        } else {
            domain = default_domain;
        }

        DEBUG(SSSDBG_TRACE_FUNC,
              "Requested domain [%s]\n", domain ? domain : "<ALL>");
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, "Splitting domain from name [%s]\n", name);

        ret = sss_parse_name(cmd_ctx, ssh_ctx->snctx, name,
                             &cmd_ctx->domname, &cmd_ctx->name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Invalid name received [%s]\n", name);
            return ENOENT;
        }

        name = cmd_ctx->name;
    }

    if (cmd_ctx->is_user && cmd_ctx->domname == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Parsing name [%s][%s]\n", name, domain ? domain : "<ALL>");

        ret = sss_parse_name_for_domains(cmd_ctx,
                                         cmd_ctx->cctx->rctx->domains,
                                         domain, name,
                                         &cmd_ctx->domname,
                                         &cmd_ctx->name);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Invalid name received [%s]\n", name);
            return ENOENT;
        }
    } else {
        if (cmd_ctx->name == NULL) {
            cmd_ctx->name = talloc_strdup(cmd_ctx, name);
            if (!cmd_ctx->name) return ENOMEM;
        }

        if (cmd_ctx->domname == NULL && domain != NULL) {
            cmd_ctx->domname = talloc_strdup(cmd_ctx, domain);
            if (!cmd_ctx->domname) return ENOMEM;
        }
    }

    if (alias != NULL && strcmp(cmd_ctx->name, alias) != 0) {
        cmd_ctx->alias = talloc_strdup(cmd_ctx, alias);
        if (!cmd_ctx->alias) return ENOMEM;
    }

    return EOK;
}

static errno_t get_valid_certs_keys(TALLOC_CTX *mem_ctx,
                                    struct ssh_cmd_ctx *cmd_ctx,
                                    struct ldb_message_element *el_cert,
                                    struct ssh_ctx *ssh_ctx,
                                    struct ldb_message_element **_el_res)
{
    TALLOC_CTX *tmp_ctx;
    uint8_t *key;
    size_t key_len;
    char *cert_verification_opts;
    struct cert_verify_opts *cert_verify_opts;
    int ret;
    struct ldb_message_element *el_res;
    struct cli_ctx *cctx = cmd_ctx->cctx;
    size_t d;

    if (el_cert == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Mssing element, nothing to do.\n");
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = confdb_get_string(cctx->rctx->cdb, tmp_ctx,
                            CONFDB_MONITOR_CONF_ENTRY,
                            CONFDB_MONITOR_CERT_VERIFICATION, NULL,
                            &cert_verification_opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to read p11_child_timeout from confdb: [%d] %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = parse_cert_verify_opts(tmp_ctx, cert_verification_opts,
                                 &cert_verify_opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to parse verifiy option.\n");
        goto done;
    }

    el_res = talloc_zero(tmp_ctx, struct ldb_message_element);
    if (el_res == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    el_res->values = talloc_array(el_res, struct ldb_val, el_cert->num_values);
    if (el_res->values == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    for (d = 0; d < el_cert->num_values; d++) {
            ret = cert_to_ssh_key(tmp_ctx, ssh_ctx->ca_db,
                                  el_cert->values[d].data,
                                  el_cert->values[d].length,
                                  cert_verify_opts, &key, &key_len);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "cert_to_ssh_key failed, ignoring.\n");
                continue;
            }

            el_res->values[el_res->num_values].data =
                                              talloc_steal(el_res->values, key);
            el_res->values[el_res->num_values].length = key_len;
            el_res->num_values++;
    }

    if (el_res->num_values == 0) {
        *_el_res = NULL;
    } else {
        *_el_res = talloc_steal(mem_ctx, el_res);
    }

    ret = EOK;

done:

    talloc_free(tmp_ctx);

    return ret;
}

static errno_t decode_and_add_base64_data(struct ssh_cmd_ctx *cmd_ctx,
                                          struct ldb_message_element *el,
                                          bool skip_base64_decode,
                                          struct ssh_ctx *ssh_ctx,
                                          size_t fqname_len,
                                          const char *fqname,
                                          size_t *c)
{
    struct cli_protocol *pctx;
    uint8_t *key;
    size_t key_len;
    uint8_t *body;
    size_t body_len;
    int ret;
    size_t d;
    TALLOC_CTX *tmp_ctx;

    if (el == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Mssing element, nothing to do.\n");
        return EOK;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    pctx = talloc_get_type(cmd_ctx->cctx->protocol_ctx, struct cli_protocol);

    for (d = 0; d < el->num_values; d++) {
        if (skip_base64_decode) {
            key = el->values[d].data;
            key_len = el->values[d].length;
        } else  {
            key = sss_base64_decode(tmp_ctx, (const char *) el->values[d].data,
                                    &key_len);
            if (key == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "sss_base64_decode failed.\n");
                ret = ENOMEM;
                goto done;
            }
        }

        ret = sss_packet_grow(pctx->creq->out,
                              3*sizeof(uint32_t) + key_len + fqname_len);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_packet_grow failed.\n");
            goto done;
        }
        sss_packet_get_body(pctx->creq->out, &body, &body_len);

        SAFEALIGN_SET_UINT32(body+(*c), 0, c);
        SAFEALIGN_SET_UINT32(body+(*c), fqname_len, c);
        safealign_memcpy(body+(*c), fqname, fqname_len, c);
        SAFEALIGN_SET_UINT32(body+(*c), key_len, c);
        safealign_memcpy(body+(*c), key, key_len, c);

    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t
ssh_cmd_build_reply(struct ssh_cmd_ctx *cmd_ctx)
{
    errno_t ret;
    uint8_t *body;
    size_t body_len;
    size_t c = 0;
    struct ldb_message_element *el = NULL;
    struct ldb_message_element *el_override = NULL;
    struct ldb_message_element *el_orig = NULL;
    struct ldb_message_element *el_user_cert = NULL;
    struct ldb_message_element *el_user_cert_keys = NULL;
    uint32_t count = 0;
    const char *name;
    char *fqname;
    uint32_t fqname_len;
    TALLOC_CTX *tmp_ctx;
    struct ssh_ctx *ssh_ctx;
    struct cli_protocol *pctx;

    ssh_ctx = talloc_get_type(cmd_ctx->cctx->rctx->pvt_ctx, struct ssh_ctx);
    pctx = talloc_get_type(cmd_ctx->cctx->protocol_ctx, struct cli_protocol);

    ret = sss_packet_new(pctx->creq, 0,
                         sss_packet_get_cmd(pctx->creq->in),
                         &pctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    el = ldb_msg_find_element(cmd_ctx->result, SYSDB_SSH_PUBKEY);
    if (el) {
        count = el->num_values;
    }

    el_orig = ldb_msg_find_element(cmd_ctx->result,
                                  ORIGINALAD_PREFIX SYSDB_SSH_PUBKEY);
    if (el_orig) {
        count = el_orig->num_values;
    }

    if (DOM_HAS_VIEWS(cmd_ctx->domain)) {
        el_override = ldb_msg_find_element(cmd_ctx->result,
                                           OVERRIDE_PREFIX SYSDB_SSH_PUBKEY);
        if (el_override) {
            count += el_override->num_values;
        }
    }

    el_user_cert = ldb_msg_find_element(cmd_ctx->result, SYSDB_USER_CERT);
    if (el_user_cert) {
        ret = get_valid_certs_keys(cmd_ctx, cmd_ctx, el_user_cert, ssh_ctx,
                                   &el_user_cert_keys);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "get_valid_certs_keys failed.\n");
            goto done;
        }

        if (el_user_cert_keys) {
            count += el_user_cert_keys->num_values;
        }
    }

    ret = sss_packet_grow(pctx->creq->out, 2*sizeof(uint32_t));
    if (ret != EOK) {
        goto done;
    }
    sss_packet_get_body(pctx->creq->out, &body, &body_len);

    SAFEALIGN_SET_UINT32(body+c, count, &c);
    SAFEALIGN_SET_UINT32(body+c, 0, &c);

    if (count == 0) {
        ret = EOK;
        goto done;
    }

    name = ldb_msg_find_attr_as_string(cmd_ctx->result, SYSDB_NAME, NULL);
    if (!name) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Got unnamed result for [%s@%s]\n",
               cmd_ctx->name, cmd_ctx->domain->name);
        ret = ENOENT;
        goto done;
    }

    fqname = talloc_asprintf(cmd_ctx, "%s@%s",
                             name, cmd_ctx->domain->name);
    if (!fqname) {
        ret = ENOMEM;
        goto done;
    }

    fqname_len = strlen(fqname)+1;

    ret = decode_and_add_base64_data(cmd_ctx, el, false, ssh_ctx,
                                     fqname_len, fqname, &c);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "decode_and_add_base64_data failed.\n");
        goto done;
    }

    ret = decode_and_add_base64_data(cmd_ctx, el_orig, false, ssh_ctx,
                                     fqname_len, fqname, &c);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "decode_and_add_base64_data failed.\n");
        goto done;
    }

    ret = decode_and_add_base64_data(cmd_ctx, el_override, false, ssh_ctx,
                                     fqname_len, fqname, &c);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "decode_and_add_base64_data failed.\n");
        goto done;
    }

    ret = decode_and_add_base64_data(cmd_ctx, el_user_cert_keys, true, ssh_ctx,
                                     fqname_len, fqname, &c);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "decode_and_add_base64_data failed.\n");
        goto done;
    }

    ret = EOK;

done:

    talloc_free(tmp_ctx);

    return ret;
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
    struct cli_protocol *pctx;
    errno_t ret;

    pctx = talloc_get_type(cmd_ctx->cctx->protocol_ctx, struct cli_protocol);

    /* create response packet */
    ret = ssh_cmd_build_reply(cmd_ctx);
    if (ret != EOK) {
        return ret;
    }

    sss_packet_set_error(pctx->creq->out, EOK);
    sss_cmd_done(cmd_ctx->cctx, cmd_ctx);

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
        DEBUG(SSSDBG_CRIT_FAILURE, "Fatal error, killing connection!\n");
        talloc_free(cmd_ctx->cctx);
        return EFAULT;
    }

    return EOK;
}

static errno_t
ssh_cmd_get_user_pubkeys_done(struct ssh_cmd_ctx *cmd_ctx,
                              errno_t ret)
{
    return ssh_cmd_done(cmd_ctx, ret);
}

static errno_t
ssh_cmd_get_host_pubkeys_done(struct ssh_cmd_ctx *cmd_ctx,
                              errno_t ret)
{
    if (ret == EOK || ret == ENOENT) {
        ssh_host_pubkeys_update_known_hosts(cmd_ctx);
    }

    return ssh_cmd_done(cmd_ctx, ret);
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
