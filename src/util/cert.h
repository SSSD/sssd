/*
   SSSD - certificate handling utils - openssl version

   Copyright (C) Sumit Bose <sbose@redhat.com> 2015

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

#include <stdint.h>
#include <talloc.h>

#include "util/util.h"
#include "lib/certmap/sss_certmap.h"

#ifndef __CERT_H__
#define __CERT_H__

errno_t sss_cert_der_to_pem(TALLOC_CTX *mem_ctx, const uint8_t *der_blob,
                            size_t der_size, char **pem, size_t *pem_size);

errno_t sss_cert_pem_to_der(TALLOC_CTX *mem_ctx, const char *pem,
                            uint8_t **der_blob, size_t *der_size);

errno_t sss_cert_derb64_to_pem(TALLOC_CTX *mem_ctx, const char *derb64,
                               char **pem, size_t *pem_size);

errno_t sss_cert_pem_to_derb64(TALLOC_CTX *mem_ctx, const char *pem,
                               char **derb64);

errno_t sss_cert_derb64_to_ldap_filter(TALLOC_CTX *mem_ctx, const char *derb64,
                                       const char *attr_name,
                                       struct sss_certmap_ctx *certmap_ctx,
                                       struct sss_domain_info *dom,
                                       char **ldap_filter);

errno_t bin_to_ldap_filter_value(TALLOC_CTX *mem_ctx,
                                 const uint8_t *blob, size_t blob_size,
                                 char **_str);

errno_t cert_to_ssh_key(TALLOC_CTX *mem_ctx, const char *ca_db,
                        const uint8_t *der_blob, size_t der_size,
                        struct cert_verify_opts *cert_verify_opts,
                        uint8_t **key, size_t *key_size);

errno_t get_ssh_key_from_cert(TALLOC_CTX *mem_ctx,
                              uint8_t *der_blob, size_t der_size,
                              uint8_t **key_blob, size_t *key_size);

struct tevent_req *cert_to_ssh_key_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        int child_debug_fd, time_t timeout,
                                        const char *ca_db,
                                        size_t cert_count,
                                        struct ldb_val *bin_certs,
                                        const char *verify_opts);

errno_t cert_to_ssh_key_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                             struct ldb_val **keys, size_t *valid_keys);
#endif /* __CERT_H__ */
