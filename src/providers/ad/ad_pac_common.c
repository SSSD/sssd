/*
    SSSD

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


#include "providers/ad/ad_pac.h"
#include "util/util.h"

errno_t ad_get_data_from_pac(TALLOC_CTX *mem_ctx,
                             uint8_t *pac_blob, size_t pac_len,
                             struct PAC_LOGON_INFO **_logon_info)
{
    DATA_BLOB blob;
    struct ndr_pull *ndr_pull;
    struct PAC_DATA *pac_data;
    enum ndr_err_code ndr_err;
    size_t c;
    int ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    blob.data = pac_blob;
    blob.length = pac_len;

    ndr_pull = ndr_pull_init_blob(&blob, tmp_ctx);
    if (ndr_pull == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ndr_pull_init_blob failed.\n");
        ret = ENOMEM;
        goto done;
    }
    ndr_pull->flags |= LIBNDR_FLAG_REF_ALLOC; /* FIXME: is this really needed ? */

    pac_data = talloc_zero(tmp_ctx, struct PAC_DATA);
    if (pac_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ndr_err = ndr_pull_PAC_DATA(ndr_pull, NDR_SCALARS|NDR_BUFFERS, pac_data);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
        DEBUG(SSSDBG_OP_FAILURE, "ndr_pull_PAC_DATA failed [%d]\n", ndr_err);
        ret =  EBADMSG;
        goto done;
    }

    for(c = 0; c < pac_data->num_buffers; c++) {
        if (pac_data->buffers[c].type == PAC_TYPE_LOGON_INFO) {
            *_logon_info = talloc_steal(mem_ctx,
                                    pac_data->buffers[c].info->logon_info.info);

            ret = EOK;
            goto done;
        }
    }

    ret = EINVAL;

done:
    talloc_free(tmp_ctx);

    return ret;
}
