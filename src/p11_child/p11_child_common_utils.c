/*
    SSSD

    Helper child to commmunicate with SmartCard -- common code

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2019 Red Hat

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
#include "p11_child/p11_child.h"

static struct cert_verify_opts *init_cert_verify_opts(TALLOC_CTX *mem_ctx)
{
    struct cert_verify_opts *cert_verify_opts;

    cert_verify_opts = talloc_zero(mem_ctx, struct cert_verify_opts);
    if (cert_verify_opts == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return NULL;
    }

    cert_verify_opts->do_ocsp = true;
    cert_verify_opts->do_verification = true;
    cert_verify_opts->ocsp_default_responder = NULL;
    cert_verify_opts->ocsp_default_responder_signing_cert = NULL;
    cert_verify_opts->crl_file = NULL;

    return cert_verify_opts;
}

#define OCSP_DEFAUL_RESPONDER "ocsp_default_responder="
#define OCSP_DEFAUL_RESPONDER_LEN (sizeof(OCSP_DEFAUL_RESPONDER) - 1)

#define OCSP_DEFAUL_RESPONDER_SIGNING_CERT \
                                          "ocsp_default_responder_signing_cert="
#define OCSP_DEFAUL_RESPONDER_SIGNING_CERT_LEN \
                                (sizeof(OCSP_DEFAUL_RESPONDER_SIGNING_CERT) - 1)
#define CRL_FILE "crl_file="
#define CRL_FILE_LEN (sizeof(CRL_FILE) -1)

errno_t parse_cert_verify_opts(TALLOC_CTX *mem_ctx, const char *verify_opts,
                               struct cert_verify_opts **_cert_verify_opts)
{
    int ret;
    TALLOC_CTX *tmp_ctx;
    char **opts;
    size_t c;
    struct cert_verify_opts *cert_verify_opts;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    cert_verify_opts = init_cert_verify_opts(tmp_ctx);
    if (cert_verify_opts == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "init_cert_verify_opts failed.\n");
        ret = ENOMEM;
        goto done;
    }

    if (verify_opts == NULL) {
        ret = EOK;
        goto done;
    }

    ret = split_on_separator(tmp_ctx, verify_opts, ',', true, true, &opts,
                             NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "split_on_separator failed.\n");
        goto done;
    }

    for (c = 0; opts[c] != NULL; c++) {
        if (strcasecmp(opts[c], "no_ocsp") == 0) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Found 'no_ocsp' option, disabling OCSP.\n");
            cert_verify_opts->do_ocsp = false;
        } else if (strcasecmp(opts[c], "no_verification") == 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Found 'no_verification' option, "
                  "disabling verification completely. "
                  "This should not be used in production.\n");
            cert_verify_opts->do_verification = false;
        } else if (strncasecmp(opts[c], OCSP_DEFAUL_RESPONDER,
                               OCSP_DEFAUL_RESPONDER_LEN) == 0) {
            cert_verify_opts->ocsp_default_responder =
                             talloc_strdup(cert_verify_opts,
                                           &opts[c][OCSP_DEFAUL_RESPONDER_LEN]);
            if (cert_verify_opts->ocsp_default_responder == NULL
                    || *cert_verify_opts->ocsp_default_responder == '\0') {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to parse ocsp_default_responder option [%s].\n",
                      opts[c]);
                ret = EINVAL;
                goto done;
            }

            DEBUG(SSSDBG_TRACE_ALL, "Using OCSP default responder [%s]\n",
                                    cert_verify_opts->ocsp_default_responder);
        } else if (strncasecmp(opts[c],
                               OCSP_DEFAUL_RESPONDER_SIGNING_CERT,
                               OCSP_DEFAUL_RESPONDER_SIGNING_CERT_LEN) == 0) {
            cert_verify_opts->ocsp_default_responder_signing_cert =
                talloc_strdup(cert_verify_opts,
                              &opts[c][OCSP_DEFAUL_RESPONDER_SIGNING_CERT_LEN]);
            if (cert_verify_opts->ocsp_default_responder_signing_cert == NULL
                    || *cert_verify_opts->ocsp_default_responder_signing_cert
                                                                      == '\0') {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to parse ocsp_default_responder_signing_cert "
                      "option [%s].\n", opts[c]);
                ret = EINVAL;
                goto done;
            }

            DEBUG(SSSDBG_TRACE_ALL,
                  "Using OCSP default responder signing cert nickname [%s]\n",
                  cert_verify_opts->ocsp_default_responder_signing_cert);
        } else if (strncasecmp(opts[c], CRL_FILE, CRL_FILE_LEN) == 0) {
            cert_verify_opts->crl_file = talloc_strdup(cert_verify_opts,
                                                       &opts[c][CRL_FILE_LEN]);
            if (cert_verify_opts->crl_file == NULL
                    || *cert_verify_opts->crl_file == '\0') {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to parse crl_file option [%s].\n", opts[c]);
                ret = EINVAL;
                goto done;
            }
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unsupported certificate verification option [%s], " \
                  "skipping.\n", opts[c]);
        }
    }

#ifdef HAVE_NSS
    if ((cert_verify_opts->ocsp_default_responder == NULL
            && cert_verify_opts->ocsp_default_responder_signing_cert != NULL)
        || (cert_verify_opts->ocsp_default_responder != NULL
            && cert_verify_opts->ocsp_default_responder_signing_cert == NULL)) {

        DEBUG(SSSDBG_CRIT_FAILURE,
              "ocsp_default_responder and ocsp_default_responder_signing_cert "
              "must be used together.\n");

        ret = EINVAL;
        goto done;
    }
#endif

    ret = EOK;

done:
    if (ret == EOK) {
        *_cert_verify_opts = talloc_steal(mem_ctx, cert_verify_opts);
    }

    talloc_free(tmp_ctx);

    return ret;
}
