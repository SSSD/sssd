/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2026 Red Hat

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

#include "config.h"

#include <errno.h>
#include <krb5/krb5.h>
#include <security/pam_appl.h>
#include <stdlib.h>

#include "sss_client/krb5_authdata_int.h"
#include "sss_client/sss_cli.h"
#include "shared/safealign.h"
#include "util/sss_bot.h"

/*
 * k5_authind_decode is exported from libkrb5 but declared in the
 * internal header k5-int.h which we cannot include. Declare it here.
 *
 * It decodes a single KRB5_AUTHDATA_AUTH_INDICATOR element (which
 * contains a DER-encoded SEQUENCE OF UTF8String) and appends the
 * decoded strings to the *indicators array, reallocating as needed.
 */
extern krb5_error_code
k5_authind_decode(const krb5_authdata *ad, krb5_data ***indicators);

/**
 * @brief IMPORTANT This is work in progress.
 *
 * It currently reads metadata from auth indicators. This will be reworked
 * into a custom Kerberos container instead when we made significant progress
 * on the IPA part.
 */

 #define AD_CAMMAC_PROTECTED     0x20

struct sssd_authdata_bot_context {
    krb5_data **indicators;
};

static void
sssd_authdata_bot_context_free_indicators(krb5_context kcontext,
                                          struct sssd_authdata_bot_context *ctx)
{
    size_t i;

    if (ctx == NULL) {
        return;
    }

    if (ctx->indicators == NULL) {
        return;
    }

    for (i = 0; ctx->indicators[i] != NULL; i++) {
        krb5_free_data(kcontext, ctx->indicators[i]);
    }
    free(ctx->indicators);

    ctx->indicators = NULL;
}

static void
sssd_authdata_bot_context_free(krb5_context kcontext,
                               struct sssd_authdata_bot_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    sssd_authdata_bot_context_free_indicators(kcontext, ctx);
    free(ctx);
}

static krb5_error_code
sssd_authdata_bot_send_metadata(krb5_context kcontext,
                                const krb5_ap_req *req,
                                struct sssd_authdata_bot_context *ctx)
{
    struct sss_cli_req_data req_data;
    struct sss_bot *bot = NULL;
    char *princ_str = NULL;
    uint8_t *body = NULL;
    krb5_error_code kerr;
    size_t bot_name_len;
    size_t body_len;
    size_t count;
    size_t rp;
    size_t i;
    int errnop = 0;
    int pam_status;
    errno_t ret;

    if (ctx->indicators == NULL) {
        return EOK;
    }

    /* Count indicators. */
    for (count = 0; ctx->indicators[count] != NULL; count++) {
        /* just counting */
    }

    if (count == 0) {
        return EOK;
    }

    /* Extract principal name and parse it to a bot account. */
    kerr = krb5_unparse_name(kcontext, req->ticket->enc_part2->client,
                             &princ_str);
    if (kerr != 0) {
        return kerr;
    }

    ret = sss_bot_cli_parse(princ_str, &bot);
    if (ret == EINVAL) {
        /* Not a bot account. */
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        /* Unable to parse the account. */
        krb5_set_error_message(kcontext, KRB5KRB_ERR_GENERIC,
                              "Failed to parse bot principal (%d): %s",
                              ret, ssscli_err2string(ret));
        goto done;
    }

    /*
     * Body: [name\0][uint32 ind_len][indicator]...
     */
    bot_name_len = strlen(bot->name) + 1;
    body_len = bot_name_len;
    for (i = 0; i < count; i++) {
        if (ctx->indicators[i]->length == 0) {
            continue;
        }

        body_len += sizeof(uint32_t);
        body_len += ctx->indicators[i]->length;
    }

    body = malloc(body_len);
    if (body == NULL) {
        ret = ENOMEM;
        krb5_set_error_message(kcontext, KRB5KRB_ERR_GENERIC,
                              "Failed to allocate bot metadata request "
                              "(%d): %s", ret, ssscli_err2string(ret));
        goto done;
    }

    rp = 0;
    SAFEALIGN_SET_STRING(&body[rp], bot->name, bot_name_len, &rp);
    for (i = 0; i < count; i++) {
        if (ctx->indicators[i]->length == 0) {
            continue;
        }

        SAFEALIGN_SET_UINT32(&body[rp], ctx->indicators[i]->length, &rp);
        SAFEALIGN_SET_STRING(&body[rp], ctx->indicators[i]->data,
                             ctx->indicators[i]->length, &rp);
    }

    req_data.len = body_len;
    req_data.data = body;

    /* Registration errors must fail authentication. */
    pam_status = sss_pam_make_request(SSS_PAM_BOT_REGISTER, &req_data,
                                      NULL, NULL, &errnop);
    if (pam_status != PAM_SUCCESS || errnop != EOK) {
        ret = errnop != EOK ? errnop : EIO;
        krb5_set_error_message(kcontext, KRB5KRB_ERR_GENERIC,
                              "Failed to register bot metadata with SSSD "
                              "(PAM status %d, error %d: %s)",
                              pam_status, errnop,
                              errnop != EOK
                                  ? ssscli_err2string(errnop)
                                  : "no additional error information");
        goto done;
    }

    ret = EOK;

done:
    krb5_free_unparsed_name(kcontext, princ_str);
    sss_bot_cli_free(bot);
    free(body);

    if (ret != EOK) {
        return KRB5KRB_ERR_GENERIC;
    }

    return 0;
}

static krb5_error_code
sssd_authdata_bot_init(krb5_context kcontext,
                       void **plugin_context)
{
    *plugin_context = NULL;
    return 0;
}

static void
sssd_authdata_bot_flags(krb5_context kcontext,
                        void *plugin_context,
                        krb5_authdatatype ad_type,
                        krb5_flags *flags)
{
    *flags = AD_CAMMAC_PROTECTED;
}

static krb5_error_code
sssd_authdata_bot_request_init(krb5_context kcontext,
                               krb5_authdata_context context,
                               void *plugin_context,
                               void **request_context)
{
    struct sssd_authdata_bot_context *ctx;

    ctx = (struct sssd_authdata_bot_context *)calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return ENOMEM;
    }

    *request_context = ctx;

    return 0;
}

static void
sssd_authdata_bot_request_fini(krb5_context kcontext,
                               krb5_authdata_context context,
                               void *plugin_context,
                               void *request_context)
{
    struct sssd_authdata_bot_context *ctx;

    ctx = (struct sssd_authdata_bot_context *)request_context;

    sssd_authdata_bot_context_free(kcontext, ctx);
}

static krb5_error_code
sssd_authdata_bot_import_authdata(krb5_context kcontext,
                                  krb5_authdata_context context,
                                  void *plugin_context,
                                  void *request_context,
                                  krb5_authdata **authdata,
                                  krb5_boolean kdc_issued,
                                  krb5_const_principal kdc_issuer)
{
    struct sssd_authdata_bot_context *ctx;
    krb5_error_code ret;
    size_t i;

    ctx = (struct sssd_authdata_bot_context *)request_context;

    sssd_authdata_bot_context_free_indicators(kcontext, ctx);

    for (i = 0; authdata != NULL && authdata[i] != NULL; i++) {
        ret = k5_authind_decode(authdata[i], &ctx->indicators);
        if (ret != 0) {
            sssd_authdata_bot_context_free_indicators(kcontext, ctx);
            return ret;
        }
    }

    return 0;
}

static krb5_error_code
sssd_authdata_bot_verify(krb5_context kcontext,
                         krb5_authdata_context context,
                         void *plugin_context,
                         void *request_context,
                         const krb5_auth_context *auth_context,
                         const krb5_keyblock *key,
                         const krb5_ap_req *req)
{
    struct sssd_authdata_bot_context *ctx;

    ctx = (struct sssd_authdata_bot_context *)request_context;

    if (ctx == NULL) {
        return 0;
    }

    return sssd_authdata_bot_send_metadata(kcontext, req, ctx);
}

/*
 * Indicators are transient: they are forwarded to the PAM responder
 * during verify() and not needed afterwards. Serialize an empty state
 * (just an indicator count of 0) so that size/externalize/internalize
 * are consistent and the context can be copied without issues.
 */

static krb5_error_code
sssd_authdata_bot_size(krb5_context kcontext,
                       krb5_authdata_context context,
                       void *plugin_context,
                       void *request_context,
                       size_t *sizep)
{
    *sizep += sizeof(krb5_int32);

    return 0;
}

static krb5_error_code
sssd_authdata_bot_externalize(krb5_context kcontext,
                              krb5_authdata_context context,
                              void *plugin_context,
                              void *request_context,
                              krb5_octet **buffer,
                              size_t *lenremain)
{
    return krb5_ser_pack_int32(0, buffer, lenremain);
}

static krb5_error_code
sssd_authdata_bot_internalize(krb5_context kcontext,
                              krb5_authdata_context context,
                              void *plugin_context,
                              void *request_context,
                              krb5_octet **buffer,
                              size_t *lenremain)
{
    krb5_int32 count;
    krb5_error_code code;

    code = krb5_ser_unpack_int32(&count, buffer, lenremain);
    if (code != 0) {
        return code;
    }

    if (count != 0) {
        return EINVAL;
    }

    return 0;
}

static krb5_authdatatype sssd_authdata_bot_ad_types[] = {
    KRB5_AUTHDATA_AUTH_INDICATOR,
    0
};

krb5plugin_authdata_client_ftable_v0 authdata_client_0 = {
    "sssd_authdata_bot",
    sssd_authdata_bot_ad_types,
    sssd_authdata_bot_init,
    NULL,
    sssd_authdata_bot_flags,
    sssd_authdata_bot_request_init,
    sssd_authdata_bot_request_fini,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    sssd_authdata_bot_import_authdata,
    NULL,
    NULL,
    sssd_authdata_bot_verify,
    sssd_authdata_bot_size,
    sssd_authdata_bot_externalize,
    sssd_authdata_bot_internalize,
    NULL
};
