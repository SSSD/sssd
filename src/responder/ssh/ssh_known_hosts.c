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

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "util/sss_ssh.h"
#include "db/sysdb.h"
#include "db/sysdb_ssh.h"
#include "responder/ssh/ssh_private.h"

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
    size_t i, j;

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

            ret = sss_generate_csprng_buffer((uint8_t *)salt, SSS_SHA1_LENGTH);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sss_generate_csprng_buffer() failed (%d)\n", ret);
                result = NULL;
                goto done;
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
ssh_write_known_hosts(struct sss_domain_info *domains,
                      bool hash_known_hosts,
                      time_t now,
                      int fd)
{
    TALLOC_CTX *tmp_ctx;
    struct sss_domain_info *dom;
    struct ldb_message **hosts;
    struct sysdb_ctx *sysdb;
    struct sss_ssh_ent *ent;
    char *entstr;
    size_t num_hosts;
    size_t i;
    ssize_t wret;
    errno_t ret;

    static const char *attrs[] = {
        SYSDB_NAME,
        SYSDB_NAME_ALIAS,
        SYSDB_SSH_PUBKEY,
        NULL
    };

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    for (dom = domains; dom != NULL; dom = get_next_domain(dom, false)) {
        sysdb = dom->sysdb;
        if (sysdb == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Fatal: Sysdb CTX not found for this domain!\n");
            ret = EFAULT;
            goto done;
        }

        ret = sysdb_get_ssh_known_hosts(tmp_ctx, dom, now, attrs,
                                        &hosts, &num_hosts);
        if (ret == ENOENT) {
            continue;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Host search failed for domain "
                  "%s [%d]: %s\n", dom->name, ret, sss_strerror(ret));
            continue;
        }

        for (i = 0; i < num_hosts; i++) {
            ret = sss_ssh_make_ent(tmp_ctx, hosts[i], &ent);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to get SSH host public keys\n");
                continue;
            }

            if (hash_known_hosts) {
                entstr = ssh_host_pubkeys_format_known_host_hashed(ent, ent);
            } else {
                entstr = ssh_host_pubkeys_format_known_host_plain(ent, ent);
            }

            if (entstr == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "Failed to format known_hosts data "
                      "for [%s]\n", ent->name);
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

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

errno_t
ssh_update_known_hosts_file(struct sss_domain_info *domains,
                            struct sss_domain_info *domain,
                            const char *name,
                            bool hash_known_hosts,
                            int known_hosts_timeout)
{
    TALLOC_CTX *tmp_ctx;
    char *filename;
    errno_t ret;
    time_t now;
    int fd = -1;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    now = time(NULL);

    /* Update host's expiration time. */
    if (domain != NULL) {
        ret = sysdb_update_ssh_known_host_expire(domain, name, now,
                                                 known_hosts_timeout);
        if (ret != EOK && ret != ENOENT) {
            goto done;
        }
    }

    /* Create temporary known hosts file. */
    filename = talloc_strdup(tmp_ctx, SSS_SSH_KNOWN_HOSTS_TEMP_TMPL);
    if (filename == NULL) {
        ret = ENOMEM;
        goto done;
    }

    fd = sss_unique_file_ex(tmp_ctx, filename, 0133, &ret);
    if (fd == -1) {
        filename = NULL;
        goto done;
    }

    /* Write contents. */
    ret = ssh_write_known_hosts(domains, hash_known_hosts, now, fd);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to write known hosts file "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }


    /* Rename to SSH known hosts file. */
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
    talloc_free(tmp_ctx);

    if (fd != -1) {
        close(fd);
    }

    return ret;
}
