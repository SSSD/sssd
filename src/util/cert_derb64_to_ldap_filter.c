/*
   SSSD - helper function with dependency to libsss_certmap.so

   Copyright (C) Sumit Bose <sbose@redhat.com> 2020

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

#include "util/util.h"
#include "util/cert.h"
#include "util/crypto/sss_crypto.h"
#include "lib/certmap/sss_certmap.h"

errno_t sss_cert_derb64_to_ldap_filter(TALLOC_CTX *mem_ctx, const char *derb64,
                                       const char *attr_name,
                                       struct sss_certmap_ctx *certmap_ctx,
                                       struct sss_domain_info *dom,
                                       char **ldap_filter)
{
    int ret;
    unsigned char *der;
    size_t der_size;
    char *val;
    char *filter = NULL;
    char **domains = NULL;
    size_t c;

    if (derb64 == NULL || attr_name == NULL) {
        return EINVAL;
    }

    der = sss_base64_decode(mem_ctx, derb64, &der_size);
    if (der == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_base64_decode failed.\n");
        return EINVAL;
    }

    if (certmap_ctx == NULL) {
        ret = bin_to_ldap_filter_value(mem_ctx, der, der_size, &val);
        talloc_free(der);
        if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "bin_to_ldap_filter_value failed.\n");
                return ret;
        }

        *ldap_filter = talloc_asprintf(mem_ctx, "(%s=%s)", attr_name, val);
        talloc_free(val);
        if (*ldap_filter == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
                return ENOMEM;
        }
    } else {
        ret = sss_certmap_get_search_filter(certmap_ctx, der, der_size,
                                            &filter, &domains);
        talloc_free(der);
        if (ret != 0) {
            if (ret == ENOENT) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Certificate does not match matching-rules.\n");
            } else {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sss_certmap_get_search_filter failed.\n");
            }
        } else {
            if (domains == NULL) {
                if (IS_SUBDOMAIN(dom)) {
                    DEBUG(SSSDBG_TRACE_FUNC,
                          "Rule applies only to local domain.\n");
                    ret = ENOENT;
                }
            } else {
                for (c = 0; domains[c] != NULL; c++) {
                    if (strcasecmp(dom->name, domains[c]) == 0) {
                        DEBUG(SSSDBG_TRACE_FUNC,
                              "Rule applies to current domain [%s].\n",
                              dom->name);
                        ret = EOK;
                        break;
                    }
                }
                if (domains[c] == NULL) {
                        DEBUG(SSSDBG_TRACE_FUNC,
                              "Rule does not apply to current domain [%s].\n",
                              dom->name);
                    ret = ENOENT;
                }
            }
        }

        if (ret == EOK) {
            *ldap_filter = talloc_strdup(mem_ctx, filter);
            if (*ldap_filter == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
            }
        }
        sss_certmap_free_filter_and_domains(filter, domains);
        return ret;
    }

    return EOK;
}
