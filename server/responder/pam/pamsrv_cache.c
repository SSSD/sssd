/*
   SSSD

   PAM cache credentials

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2009
   Copyright (C) Sumit Bose <sbose@redhat.com>	2009

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

#include <security/pam_modules.h>
#include <time.h>
#include "util/util.h"
#include "db/sysdb.h"
#include "util/nss_sha512crypt.h"
#include "providers/data_provider.h"
#include "responder/pam/pamsrv.h"

static int authtok2str(const void *mem_ctx,
                       uint8_t *src, const int src_size,
                       char **_dest)
{
    char *dest;

    if ((src == NULL && src_size != 0) ||
        (src != NULL && *src != '\0' && src_size == 0)) {
        return EINVAL;
    }

    dest = talloc_size(mem_ctx, src_size + 1);
    if (dest == NULL) {
        return ENOMEM;
    }

    memcpy(dest, src, src_size);
    dest[src_size]='\0';

    *_dest = dest;
    return EOK;
}

static void pam_cache_auth_return(struct pam_auth_req *preq, int error)
{
    preq->pd->pam_status = error;
    preq->callback(preq);
}

static void pam_cache_auth_callback(void *pvt, int ldb_status,
                                    struct ldb_result *res)
{
    struct pam_auth_req *preq;
    struct pam_ctx *pctx;
    struct pam_data *pd;
    const char *userhash;
    char *comphash;
    char *password = NULL;
    int i, ret;
    uint64_t lastLogin = 0;

    preq = talloc_get_type(pvt, struct pam_auth_req);
    pd = preq->pd;

    pctx = talloc_get_type(preq->cctx->rctx->pvt_ctx, struct pam_ctx);

    if (ldb_status != LDB_SUCCESS) {
        DEBUG(4, ("User info retrieval failed! (%d [%s])\n",
                  ldb_status, sysdb_error_to_errno(ldb_status)));

        ret = PAM_SYSTEM_ERR;
        goto done;
    }

    if (res->count == 0) {
        DEBUG(4, ("User [%s@%s] not found.\n",
                  pd->user, preq->domain->name));
        ret = PAM_USER_UNKNOWN;
        goto done;
    }

    if (res->count != 1) {
        DEBUG(4, ("Too many results for user [%s@%s].\n",
                  pd->user, preq->domain->name));
        ret = PAM_SYSTEM_ERR;
        goto done;
    }

    /* Check offline_auth_cache_timeout */
    lastLogin = ldb_msg_find_attr_as_uint64(res->msgs[0],
                                            SYSDB_LAST_ONLINE_AUTH,
                                            0);
    if (pctx->cred_expiration &&
        lastLogin + (pctx->cred_expiration * 86400) < time(NULL)) {
        DEBUG(4, ("Cached user entry is too old."));
        ret = PAM_AUTHINFO_UNAVAIL;
        goto done;
    }

    /* TODO: verify user account (failed logins, disabled, expired ...) */

    ret = authtok2str(preq, pd->authtok, pd->authtok_size, &password);
    if (ret) {
        DEBUG(4, ("Invalid auth token.\n"));
        ret = PAM_AUTH_ERR;
        goto done;
    }

    userhash = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_CACHEDPWD, NULL);
    if (userhash == NULL || *userhash == '\0') {
        DEBUG(4, ("Cached credentials not available.\n"));
        ret = PAM_AUTHINFO_UNAVAIL;
        goto done;
    }

    ret = s3crypt_sha512(preq, password, userhash, &comphash);
    if (ret) {
        DEBUG(4, ("Failed to create password hash.\n"));
        ret = PAM_SYSTEM_ERR;
        goto done;
    }

    if (strcmp(userhash, comphash) == 0) {
        /* TODO: probable good point for audit logging */
        DEBUG(4, ("Hashes do match!\n"));
        ret = PAM_SUCCESS;
        goto done;
    }

    DEBUG(4, ("Authentication failed.\n"));
    ret = PAM_AUTH_ERR;

done:
    if (password) for (i = 0; password[i]; i++) password[i] = 0;
    pam_cache_auth_return(preq, ret);
}

int pam_cache_auth(struct pam_auth_req *preq)
{
    struct sysdb_ctx *sysdb;
    int ret;

    static const char *attrs[] = {SYSDB_NAME,
                                  SYSDB_CACHEDPWD,
                                  SYSDB_DISABLED,
                                  SYSDB_LAST_LOGIN,
                                  SYSDB_LAST_ONLINE_AUTH,
                                  "lastCachedPasswordChange",
                                  "accountExpires",
                                  "failedLoginAttempts",
                                  "lastFailedLogin",
                                  NULL};

    ret = sysdb_get_ctx_from_list(preq->cctx->rctx->db_list,
                                  preq->domain, &sysdb);
    if (ret != EOK) {
        DEBUG(0, ("Fatal: Sysdb CTX not found for this domain!\n"));
        return ret;
    }
    ret = sysdb_get_user_attr(preq, sysdb,
                              preq->domain, preq->pd->user, attrs,
                              pam_cache_auth_callback, preq);

    if (ret != EOK) {
        DEBUG(2, ("sysdb_get_user_attr failed.\n"));
    }

    return ret;
}

