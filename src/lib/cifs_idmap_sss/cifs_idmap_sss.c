/*
    Authors:
        Benjamin Franzke <benjaminfranzke@googlemail.com>

    Copyright (C) 2013 Benjamin Franzke

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

/* TODO: Support of [all] samba's Unix SIDs:
 *         Users:  S-1-22-1-%UID
 *         Groups: S-1-22-2-%GID
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdarg.h>

#include <cifsidmap.h>

#include "lib/idmap/sss_idmap.h"
#include "sss_client/idmap/sss_nss_idmap.h"

#ifdef DEBUG
#include <syslog.h>
#define debug(str, ...) \
    syslog(0, "%s: " str "\n", \
           __FUNCTION__, ##__VA_ARGS__)
#else
#define debug(...) do { } while(0)
#endif

struct sssd_ctx {
    struct sss_idmap_ctx *idmap;
    const char **errmsg;
};

#define ctx_set_error(ctx, error) \
    do { \
        *ctx->errmsg = error; \
        debug("%s", error ? error : ""); \
    } while (0);

int cifs_idmap_init_plugin(void **handle, const char **errmsg)
{
    struct sssd_ctx *ctx;
    enum idmap_error_code err;

    if (handle == NULL || errmsg == NULL)
        return EINVAL;

    ctx = malloc(sizeof *ctx);
    if (!ctx) {
        *errmsg = "Failed to allocate context";
        return -1;
    }
    ctx->errmsg = errmsg;
    ctx_set_error(ctx, NULL);

    err = sss_idmap_init(NULL, NULL, NULL, &ctx->idmap);
    if (err != IDMAP_SUCCESS) {
        ctx_set_error(ctx, idmap_error_string(err));
        free(ctx);
        return -1;
    }

    *handle = ctx;
    return 0;
}

void cifs_idmap_exit_plugin(void *handle)
{
    struct sssd_ctx *ctx = handle;

    debug("exit");

    if (ctx == NULL)
        return;

    sss_idmap_free(ctx->idmap);

    free(ctx);
}


/* Test with `getcifsacl file` on client. */
int cifs_idmap_sid_to_str(void *handle, const struct cifs_sid *csid,
                          char **name)
{
    struct sssd_ctx *ctx = handle;
    enum idmap_error_code iderr;
    char *sid;
    enum sss_id_type id_type;
    int err;

    iderr = sss_idmap_bin_sid_to_sid(ctx->idmap, (const uint8_t *) csid,
                                     sizeof(*csid), &sid);
    if (iderr != IDMAP_SUCCESS) {
        ctx_set_error(ctx, idmap_error_string(iderr));
        *name = NULL;
        return -1;
    }

    debug("sid: %s", sid);

    err = sss_nss_getnamebysid(sid, name, &id_type);
    if (err != 0)  {
        ctx_set_error(ctx, strerror(err));
        *name = NULL;
        return -err;
    }

    /* FIXME: Map Samba Unix SIDs? (sid->id and use getpwuid)? */

    debug("name: %s", *name);

    return 0;
}

static int sid_to_cifs_sid(struct sssd_ctx *ctx, const char *sid,
                           struct cifs_sid *csid)
{
    uint8_t *bsid = NULL;
    enum idmap_error_code err;
    size_t length;

    err = sss_idmap_sid_to_bin_sid(ctx->idmap,
                                   sid, &bsid, &length);
    if (err != IDMAP_SUCCESS) {
        ctx_set_error(ctx, idmap_error_string(err));
        return -1;
    }
    if (length > sizeof(struct cifs_sid)) {
        ctx_set_error(ctx, "too large sid length");
        free(bsid);
        return -1;
    }

    memcpy(csid, bsid, length);
    sss_idmap_free_bin_sid(ctx->idmap, bsid);

    return 0;
}

/* Test with setcifsacl -a */
int cifs_idmap_str_to_sid(void *handle, const char *name,
                          struct cifs_sid *csid)
{
    struct sssd_ctx *ctx = handle;
    int err;
    enum sss_id_type id_type;
    char *sid = NULL;
    int success = 0;

    debug("%s", name);

    err = sss_nss_getsidbyname(name, &sid, &id_type);
    if (err != 0)  {
        /* Might be a raw string representation of SID,
         * try converting that before returning an error. */
        if (sid_to_cifs_sid(ctx, name, csid) == 0)
            return 0;

        ctx_set_error(ctx, strerror(err));
        return -err;
    }

    if (sid_to_cifs_sid(ctx, sid, csid) != 0)
        success = -1;

    free(sid);

    return success;
}

static int samba_unix_sid_to_id(const char *sid, struct cifs_uxid *cuxid)
{
    id_t id;
    uint8_t type;

    if (sscanf(sid, "S-1-22-%hhu-%u", &type, &id) != 2)
        return -1;

    switch (type) {
    case 1:
        cuxid->type = CIFS_UXID_TYPE_UID;
        cuxid->id.uid = id;
        break;
    case 2:
        cuxid->type = CIFS_UXID_TYPE_GID;
        cuxid->id.gid = id;
        break;
    default:
        cuxid->type = CIFS_UXID_TYPE_UNKNOWN;
        return -1;
    }

    return 0;
}

static int sss_sid_to_id(struct sssd_ctx *ctx, const char *sid,
                         struct cifs_uxid *cuxid)
{
    int err;
    enum sss_id_type id_type;
    uint32_t uid;

    err = sss_nss_getidbysid(sid, &uid, &id_type);
    if (err != 0)  {
        ctx_set_error(ctx, strerror(err));
        return -1;
    }
    cuxid->id.uid = (uid_t)uid;

    switch (id_type) {
    case SSS_ID_TYPE_UID:
        cuxid->type = CIFS_UXID_TYPE_UID;
        break;
    case SSS_ID_TYPE_GID:
        cuxid->type = CIFS_UXID_TYPE_GID;
        break;
    case SSS_ID_TYPE_BOTH:
        cuxid->type = CIFS_UXID_TYPE_BOTH;
        break;
    case SSS_ID_TYPE_NOT_SPECIFIED:
    default:
        return -1;
    }

    return 0;
}

/**
 * cifs_idmap_sids_to_ids - convert struct cifs_sids to struct cifs_uxids
 * usecase: mount.cifs -o sec=krb5,multiuser,cifsacl,nounix
 * test: ls -n on mounted share
 */
int cifs_idmap_sids_to_ids(void *handle, const struct cifs_sid *csid,
                           const size_t num, struct cifs_uxid *cuxid)
{
    struct sssd_ctx *ctx = handle;
    enum idmap_error_code err;
    int success = -1;
    size_t i;
    char *sid;

    debug("num: %zd", num);

    if (num > UINT_MAX) {
        ctx_set_error(ctx, "num is too large.");
        return EINVAL;
    }

    for (i = 0; i < num; ++i) {
        err = sss_idmap_bin_sid_to_sid(ctx->idmap, (const uint8_t *) &csid[i],
                                       sizeof(csid[i]), &sid);
        if (err != IDMAP_SUCCESS) {
            ctx_set_error(ctx, idmap_error_string(err));
            continue;
        }

        cuxid[i].type = CIFS_UXID_TYPE_UNKNOWN;

        if (sss_sid_to_id(ctx, sid, &cuxid[i]) == 0 ||
            samba_unix_sid_to_id(sid, &cuxid[i]) == 0) {

            debug("setting uid of %s to %d", sid, cuxid[i].id.uid);
            success = 0;
        }

        free(sid);
    }

    return success;
}


int cifs_idmap_ids_to_sids(void *handle, const struct cifs_uxid *cuxid,
                           const size_t num, struct cifs_sid *csid)
{
    struct sssd_ctx *ctx = handle;
    int err, success = -1;
    char *sid;
    enum sss_id_type id_type;
    size_t i;

    debug("num ids: %zd", num);

    if (num > UINT_MAX) {
        ctx_set_error(ctx, "num is too large.");
        return EINVAL;
    }

    for (i = 0; i < num; ++i) {
        switch (cuxid[i].type) {
        case CIFS_UXID_TYPE_UID:
            err = sss_nss_getsidbyuid((uint32_t)cuxid[i].id.uid,
                                      &sid, &id_type);
            break;
        case CIFS_UXID_TYPE_GID:
            err = sss_nss_getsidbygid((uint32_t)cuxid[i].id.gid,
                                      &sid, &id_type);
            break;
        default:
            err = sss_nss_getsidbyid((uint32_t)cuxid[i].id.uid, &sid, &id_type);
        }
        if (err != 0)  {
            ctx_set_error(ctx, strerror(err));
            csid[i].revision = 0;
            /* FIXME: would it be safe to map *any* uid/gids unknown by sssd to
             * SAMBA's UNIX SIDs? */
            continue;
        }

        if (sid_to_cifs_sid(ctx, sid, csid) == 0)
            success = 0;
        else
            csid[i].revision = 0;
        free(sid);
    }

    return success;
}
