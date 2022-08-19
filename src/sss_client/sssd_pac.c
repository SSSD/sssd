/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2011, 2012, 2013 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* A short documentation about authdata plugins can be found in
 * http://http://k5wiki.kerberos.org/wiki/Projects/VerifyAuthData */

#include <krb5/krb5.h>
#include <errno.h>

#include "krb5_authdata_int.h"
#include "sss_cli.h"


struct sssd_context {
    krb5_data data;
};

static krb5_error_code
sssdpac_init(krb5_context kcontext, void **plugin_context)
{
    *plugin_context = NULL;
    return 0;
}

static void
sssdpac_flags(krb5_context kcontext,
              void *plugin_context,
              krb5_authdatatype ad_type,
              krb5_flags *flags)
{
    *flags = AD_USAGE_KDC_ISSUED | AD_USAGE_TGS_REQ;
}

static void
sssdpac_fini(krb5_context kcontext, void *plugin_context)
{
    return;
}

static krb5_error_code
sssdpac_request_init(krb5_context kcontext,
                     krb5_authdata_context context,
                     void *plugin_context,
                     void **request_context)
{
    struct sssd_context *sssdctx;

    sssdctx = (struct sssd_context *)calloc(1, sizeof(*sssdctx));
    if (sssdctx == NULL) {
        return ENOMEM;
    }

    *request_context = sssdctx;

    return 0;
}

static krb5_error_code
sssdpac_import_authdata(krb5_context kcontext,
                        krb5_authdata_context context,
                        void *plugin_context,
                        void *request_context,
                        krb5_authdata **authdata,
                        krb5_boolean kdc_issued,
                        krb5_const_principal kdc_issuer)
{
    char *data = NULL;
    struct sssd_context *sssdctx = (struct sssd_context *)request_context;

    if (authdata[0] == NULL) {
        return EINVAL;
    }

    if (authdata[0]->length > 0) {
        data = malloc(sizeof(char) * authdata[0]->length);
        if (data == NULL) {
            return ENOMEM;
        }
        memcpy(data, authdata[0]->contents, authdata[0]->length);
    }

    if (sssdctx->data.data != NULL) {
        krb5_free_data_contents(kcontext, &sssdctx->data);
    }

    sssdctx->data.length = authdata[0]->length;
    sssdctx->data.data = data;
    return 0;
}

static void
sssdpac_request_fini(krb5_context kcontext,
                     krb5_authdata_context context,
                     void *plugin_context,
                     void *request_context)
{
    struct sssd_context *sssdctx = (struct sssd_context *)request_context;

    if (sssdctx != NULL) {
        if (sssdctx->data.data != NULL) {
            krb5_free_data_contents(kcontext, &sssdctx->data);
        }

        free(sssdctx);
    }
}

static krb5_error_code sssdpac_verify(krb5_context kcontext,
                                      krb5_authdata_context context,
                                      void *plugin_context,
                                      void *request_context,
                                      const krb5_auth_context *auth_context,
                                      const krb5_keyblock *key,
                                      const krb5_ap_req *req)
{
    krb5_error_code kerr;
    int ret;
    krb5_pac pac;
    struct sssd_context *sssdctx = (struct sssd_context *)request_context;
    struct sss_cli_req_data sss_data;
    int errnop;

    if (sssdctx == NULL || sssdctx->data.data == NULL) {
        return EINVAL;
    }

    kerr = krb5_pac_parse(kcontext, sssdctx->data.data,
                          sssdctx->data.length, &pac);
    if (kerr != 0) {
        return EINVAL;
    }

    kerr = krb5_pac_verify(kcontext, pac,
                           req->ticket->enc_part2->times.authtime,
                           req->ticket->enc_part2->client, key, NULL);
    /* deallocate pac */
    krb5_pac_free(kcontext, pac);
    pac = NULL;
    if (kerr != 0) {
        /* The krb5 documentation says:
         * A checksum mismatch can occur if the PAC was copied from a
         * cross-realm TGT by an ignorant KDC; also Apple Mac OS X Server
         * Open Directory (as of 10.6) generates PACs with no server checksum
         * at all. One should consider not failing the whole authentication
         * because of this reason, but, instead, treating the ticket as
         * if it did not contain a PAC or marking the PAC information as
         * non-verified.
         */
        return 0;
    }

    sss_data.len = sssdctx->data.length;
    sss_data.data = sssdctx->data.data;

    ret = sss_pac_make_request_with_lock(SSS_PAC_ADD_PAC_USER, &sss_data,
                                         NULL, NULL, &errnop);
    if (ret != 0) {
        /* Ignore the error */
    }

    return 0;
}

static krb5_error_code
sssdpac_size(krb5_context kcontext,
             krb5_authdata_context context,
             void *plugin_context,
             void *request_context,
             size_t *sizep)
{
    struct sssd_context *sssdctx = (struct sssd_context *)request_context;

    *sizep += sizeof(krb5_int32);

    *sizep += sssdctx->data.length;

    *sizep += sizeof(krb5_int32);

    return 0;
}

static krb5_error_code
sssdpac_externalize(krb5_context kcontext,
                    krb5_authdata_context context,
                    void *plugin_context,
                    void *request_context,
                    krb5_octet **buffer,
                    size_t *lenremain)
{
    krb5_error_code code = 0;
    struct sssd_context *sssdctx = (struct sssd_context *)request_context;
    size_t required = 0;
    krb5_octet *bp;
    size_t remain;

    bp = *buffer;
    remain = *lenremain;

    if (sssdctx->data.data != NULL) {
        sssdpac_size(kcontext, context, plugin_context,
                   request_context, &required);

        if (required <= remain) {
            krb5_ser_pack_int32((krb5_int32)sssdctx->data.length,
                                &bp, &remain);
            krb5_ser_pack_bytes((krb5_octet *)sssdctx->data.data,
                                (size_t)sssdctx->data.length,
                                &bp, &remain);
            krb5_ser_pack_int32(0,
                                &bp, &remain);
        } else {
            code = ENOMEM;
        }
    } else {
        krb5_ser_pack_int32(0, &bp, &remain); /* length */
        krb5_ser_pack_int32(0, &bp, &remain); /* verified */
    }

    *buffer = bp;
    *lenremain = remain;

    return code;
}

static krb5_error_code
sssdpac_internalize(krb5_context kcontext,
                    krb5_authdata_context context,
                    void *plugin_context,
                    void *request_context,
                    krb5_octet **buffer,
                    size_t *lenremain)
{
    struct sssd_context *sssdctx = (struct sssd_context *)request_context;
    krb5_error_code code;
    krb5_int32 ibuf;
    krb5_octet *bp;
    size_t remain;
    krb5_data data;

    bp = *buffer;
    remain = *lenremain;

    /* length */
    code = krb5_ser_unpack_int32(&ibuf, &bp, &remain);
    if (code != 0) {
        return code;
    }

    if (ibuf != 0) {

        data.length = ibuf;
        data.data = malloc(sizeof(char) * ibuf);
        if (data.data == NULL) {
            return ENOMEM;
        }
        memcpy(data.data, bp, ibuf);

        bp += ibuf;
        remain -= ibuf;
    } else {
        data.length = 0;
        data.data = NULL;
    }

    /* verified */
    code = krb5_ser_unpack_int32(&ibuf, &bp, &remain);
    if (code != 0) {
        free(data.data);
        return code;
    }

    if (sssdctx->data.data != NULL) {
        krb5_free_data_contents(kcontext, &sssdctx->data);
    }

    sssdctx->data.length = data.length;
    sssdctx->data.data = data.data;

    *buffer = bp;
    *lenremain = remain;

    return 0;
}

static krb5_authdatatype sssdpac_ad_types[] = { KRB5_AUTHDATA_WIN2K_PAC, 0 };

krb5plugin_authdata_client_ftable_v0 authdata_client_0 = {
    "sssd_sssdpac",
    sssdpac_ad_types,
    sssdpac_init,
    sssdpac_fini,
    sssdpac_flags,
    sssdpac_request_init,
    sssdpac_request_fini,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    sssdpac_import_authdata,
    NULL,
    NULL,
    sssdpac_verify,
    sssdpac_size,
    sssdpac_externalize,
    sssdpac_internalize,
    NULL
};
