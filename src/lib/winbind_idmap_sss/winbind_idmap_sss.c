/*
    SSSD

    ID-mapping plugin for winbind

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#include <string.h>
#include <errno.h>

#include "lib/winbind_idmap_sss/winbind_idmap_sss.h"
#include "sss_client/idmap/sss_nss_idmap.h"
#include "lib/idmap/sss_idmap.h"
#include "util/util_sss_idmap.h"

struct idmap_sss_ctx {
    struct sss_idmap_ctx *idmap_ctx;
};

static NTSTATUS idmap_sss_initialize(struct idmap_domain *dom)
{
    struct idmap_sss_ctx *ctx;
    enum idmap_error_code err;

    if (dom == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    ctx = talloc_zero(dom, struct idmap_sss_ctx);
    if (ctx == NULL) {
        return NT_STATUS_NO_MEMORY;
    }

    err = sss_idmap_init(sss_idmap_talloc, ctx, sss_idmap_talloc_free,
                         &ctx->idmap_ctx);
    if (err != IDMAP_SUCCESS) {
        talloc_free(ctx);
        return NT_STATUS_NO_MEMORY;
    }

#if SMB_IDMAP_INTERFACE_VERSION == 6
    dom->query_user = NULL;
#endif

    dom->private_data = ctx;

    return NT_STATUS_OK;
}

static NTSTATUS idmap_sss_unixids_to_sids(struct idmap_domain *dom,
                                          struct id_map **map)
{
    size_t c;
    int ret;
    char *sid_str;
    enum sss_id_type id_type;
    struct dom_sid *sid;
    enum idmap_error_code err;
    struct idmap_sss_ctx *ctx;

    if (dom == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    ctx = talloc_get_type(dom->private_data, struct idmap_sss_ctx);
    if (ctx == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    for (c = 0; map[c]; c++) {
        map[c]->status = ID_UNKNOWN;
    }

    for (c = 0; map[c]; c++) {
        switch (map[c]->xid.type) {
        case ID_TYPE_UID:
            ret = sss_nss_getsidbyuid(map[c]->xid.id, &sid_str, &id_type);
            break;
        case ID_TYPE_GID:
            ret = sss_nss_getsidbygid(map[c]->xid.id, &sid_str, &id_type);
            break;
        default:
            ret = sss_nss_getsidbyid(map[c]->xid.id, &sid_str, &id_type);
        }
        if (ret != 0) {
            if (ret == ENOENT) {
                map[c]->status = ID_UNMAPPED;
            }
            continue;
        }

        switch (id_type) {
        case SSS_ID_TYPE_UID:
            map[c]->xid.type = ID_TYPE_UID;
            break;
        case SSS_ID_TYPE_GID:
            map[c]->xid.type = ID_TYPE_GID;
            break;
        case SSS_ID_TYPE_BOTH:
            map[c]->xid.type = ID_TYPE_BOTH;
            break;
        default:
            free(sid_str);
            continue;
        }

        err = sss_idmap_sid_to_smb_sid(ctx->idmap_ctx, sid_str, &sid);
        free(sid_str);
        if (err != IDMAP_SUCCESS) {
            continue;
        }

        memcpy(map[c]->sid, sid, sizeof(struct dom_sid));
        sss_idmap_free_smb_sid(ctx->idmap_ctx, sid);

        map[c]->status = ID_MAPPED;
    }

    return NT_STATUS_OK;
}

static NTSTATUS idmap_sss_sids_to_unixids(struct idmap_domain *dom,
                                          struct id_map **map)
{
    size_t c;
    int ret;
    char *sid_str;
    enum sss_id_type id_type;
    enum idmap_error_code err;
    struct idmap_sss_ctx *ctx;
    uint32_t id;

    if (dom == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    ctx = talloc_get_type(dom->private_data, struct idmap_sss_ctx);
    if (ctx == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    for (c = 0; map[c]; c++) {
        map[c]->status = ID_UNKNOWN;
    }

    for (c = 0; map[c]; c++) {
        err = sss_idmap_smb_sid_to_sid(ctx->idmap_ctx, map[c]->sid, &sid_str);
        if (err != IDMAP_SUCCESS) {
            continue;
        }

        ret = sss_nss_getidbysid(sid_str, &id, &id_type);
        sss_idmap_free_sid(ctx->idmap_ctx, sid_str);
        if (ret != 0) {
            if (ret == ENOENT) {
                map[c]->status = ID_UNMAPPED;
            }
            continue;
        }

        switch (id_type) {
        case SSS_ID_TYPE_UID:
            map[c]->xid.type = ID_TYPE_UID;
            break;
        case SSS_ID_TYPE_GID:
            map[c]->xid.type = ID_TYPE_GID;
            break;
        case SSS_ID_TYPE_BOTH:
            map[c]->xid.type = ID_TYPE_BOTH;
            break;
        default:
            continue;
        }

        map[c]->xid.id = id;

        map[c]->status = ID_MAPPED;
    }

    return NT_STATUS_OK;
}

static struct idmap_methods sss_methods = {
    .init = idmap_sss_initialize,
    .unixids_to_sids = idmap_sss_unixids_to_sids,
    .sids_to_unixids = idmap_sss_sids_to_unixids,
};

#if SMB_IDMAP_INTERFACE_VERSION == 5
NTSTATUS idmap_sss_init(void)
#elif SMB_IDMAP_INTERFACE_VERSION == 6
NTSTATUS idmap_sss_init(TALLOC_CTX *ctx)
#else
#error Unexpected Samba idmpa inferface version
#endif
{
    return smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, "sss", &sss_methods);
}

NTSTATUS samba_init_module(void)
{
    return smb_register_idmap(SMB_IDMAP_INTERFACE_VERSION, "sss", &sss_methods);
}
