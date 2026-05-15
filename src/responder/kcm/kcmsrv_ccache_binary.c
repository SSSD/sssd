/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2020 Red Hat

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

#include <stdio.h>
#include <talloc.h>

#include "util/util.h"
#include "util/util_creds.h"
#include "util/crypto/sss_crypto.h"
#include "responder/kcm/kcmsrv_ccache_pvt.h"

static errno_t krb_data_to_bin(krb5_data *data, struct sss_iobuf *buf)
{
    return sss_iobuf_write_varlen(buf, (uint8_t *)data->data, data->length);
}

static errno_t princ_to_bin(krb5_principal princ, struct sss_iobuf *buf)
{
    errno_t ret;

    if (princ == NULL) {
        return sss_iobuf_write_uint8(buf, 0);
    }

    /* Mark that principal is not empty. */
    ret = sss_iobuf_write_uint8(buf, 1);
    if (ret != EOK) {
        return ret;
    }

    ret = krb_data_to_bin(&princ->realm, buf);
    if (ret != EOK) {
        return ret;
    }

    ret = sss_iobuf_write_int32(buf, princ->type);
    if (ret != EOK) {
        return ret;
    }

    ret = sss_iobuf_write_int32(buf, princ->length);
    if (ret != EOK) {
        return ret;
    }

    for (krb5_int32 i = 0; i < princ->length; i++) {
        ret = krb_data_to_bin(&princ->data[i], buf);
        if (ret != EOK) {
            return ret;
        }
    }

    return EOK;
}

static errno_t creds_to_bin(struct kcm_cred *creds, struct sss_iobuf *buf)
{
    struct kcm_cred *crd;
    uint32_t count = 0;
    errno_t ret;

    DLIST_FOR_EACH(crd, creds) {
        count++;
    }

    ret = sss_iobuf_write_uint32(buf, count);
    if (ret != EOK) {
        return ret;
    }

    DLIST_FOR_EACH(crd, creds) {
        ret = sss_iobuf_write_len(buf, (uint8_t *)crd->uuid, sizeof(uuid_t));
        if (ret != EOK) {
            return ret;
        }

        ret = sss_iobuf_write_iobuf(buf, crd->cred_blob);
        if (ret != EOK) {
            return ret;
        }
    }

    return EOK;
}

errno_t kcm_ccache_to_sec_input_binary(TALLOC_CTX *mem_ctx,
                                       struct kcm_ccache *cc,
                                       struct sss_iobuf **_payload)
{
    struct sss_iobuf *buf;
    errno_t ret;

    buf = sss_iobuf_init_empty(mem_ctx, sizeof(krb5_principal_data), 0);
    if (buf == NULL) {
        return ENOMEM;
    }

    ret = sss_iobuf_write_int32(buf, cc->kdc_offset);
    if (ret != EOK) {
        goto done;
    }

    ret = princ_to_bin(cc->client, buf);
    if (ret != EOK) {
        goto done;
    }

    ret = creds_to_bin(cc->creds, buf);
    if (ret != EOK) {
        goto done;
    }

    *_payload = buf;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(buf);
    }

    return ret;
}

errno_t bin_to_krb_data(TALLOC_CTX *mem_ctx,
                        struct sss_iobuf *buf,
                        krb5_data *out)
{
    uint8_t *data;
    size_t len;
    errno_t ret;

    ret = sss_iobuf_read_varlen(mem_ctx, buf, &data, &len);
    if (ret != EOK) {
        return ret;
    }

    out->magic = 0;
    out->data = (char*)data;
    out->length = len;

    return EOK;
}

static errno_t bin_to_princ(TALLOC_CTX *mem_ctx,
                            struct sss_iobuf *buf,
                            krb5_principal *_princ)
{
    krb5_principal princ;
    uint8_t non_empty;
    krb5_int32 i;
    errno_t ret;

    ret = sss_iobuf_read_uint8(buf, &non_empty);
    if (ret != EOK) {
        return ret;
    }

    if (non_empty == 0) {
        *_princ = NULL;
        return EOK;
    }

    princ = talloc_zero(mem_ctx, struct krb5_principal_data);
    if (princ == NULL) {
        return ENOMEM;
    }
    princ->magic = KV5M_PRINCIPAL;

    ret = bin_to_krb_data(princ, buf, &princ->realm);
    if (ret != EOK) {
        return ret;
    }

    ret = sss_iobuf_read_int32(buf, &princ->type);
    if (ret != EOK) {
        return ret;
    }

    ret = sss_iobuf_read_int32(buf, &princ->length);
    if (ret != EOK) {
        return ret;
    }

    princ->data = talloc_array(princ, krb5_data, princ->length);
    if (princ->length > 0 && princ->data == NULL) {
        return ENOMEM;
    }

    for (i = 0; i < princ->length; i++) {
        ret = bin_to_krb_data(princ, buf, &princ->data[i]);
        if (ret != EOK) {
            return ret;
        }
    }

    *_princ = princ;

    return EOK;
}

static errno_t bin_to_creds(TALLOC_CTX *mem_ctx,
                            struct sss_iobuf *buf,
                            struct kcm_cred **_creds)
{
    struct kcm_cred *creds = NULL;
    struct kcm_cred *crd;
    struct sss_iobuf *cred_blob;
    uint32_t count;
    uuid_t uuid;
    errno_t ret;

    ret = sss_iobuf_read_uint32(buf, &count);
    if (ret != EOK) {
        return ret;
    }

    for (uint32_t i = 0; i < count; i++) {
        ret = sss_iobuf_read_len(buf, sizeof(uuid_t), (uint8_t*)uuid);
        if (ret != EOK) {
            return ret;
        }

        ret = sss_iobuf_read_iobuf(NULL, buf, &cred_blob);
        if (ret != EOK) {
            return ret;
        }

        crd = kcm_cred_new(mem_ctx, uuid, cred_blob);
        if (crd == NULL) {
            talloc_free(cred_blob);
            return ENOMEM;
        }

        DLIST_ADD(creds, crd);
    }

    *_creds = creds;

    return EOK;
}

errno_t sec_kv_to_ccache_binary(TALLOC_CTX *mem_ctx,
                                const char *sec_key,
                                struct sss_iobuf *sec_value,
                                struct cli_creds *client,
                                struct kcm_ccache **_cc)
{
    struct kcm_ccache *cc;
    errno_t ret;

    cc = talloc_zero(mem_ctx, struct kcm_ccache);
    if (cc == NULL) {
        return ENOMEM;
    }

    ret = kcm_cc_set_header(cc, sec_key, client);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot store ccache header [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = sss_iobuf_read_int32(sec_value, &cc->kdc_offset);
    if  (ret != EOK) {
        goto done;
    }

    ret = bin_to_princ(cc, sec_value, &cc->client);
    if  (ret != EOK) {
        goto done;
    }

    ret = bin_to_creds(cc, sec_value, &cc->creds);
    if  (ret != EOK) {
        goto done;
    }

    *_cc = cc;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(cc);
    }

    return ret;
}
