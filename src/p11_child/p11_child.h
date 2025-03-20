/*
    SSSD

    Helper child to commmunicate with SmartCard

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2018 Red Hat

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

#ifndef __P11_CHILD_H__
#define __P11_CHILD_H__

/* for CK_MECHANISM_TYPE */
#include <p11-kit/pkcs11.h>
#include <time.h>

/* Time to wait for new slot events. */
#define PKCS11_SLOT_EVENT_WAIT_TIME 1
struct p11_ctx;

struct cert_verify_opts {
    bool do_ocsp;
    bool do_verification;
    bool verification_partial_chain;
    char *ocsp_default_responder;
    char *ocsp_default_responder_signing_cert;
    char **crl_files;
    int num_files;
    CK_MECHANISM_TYPE ocsp_dgst;
    bool soft_ocsp;
    bool soft_crl;
};

enum op_mode {
    OP_NONE,
    OP_AUTH,
    OP_PREAUTH,
    OP_VERIFIY
};

enum pin_mode {
    PIN_NONE,
    PIN_STDIN,
    PIN_KEYPAD
};

errno_t init_p11_ctx(TALLOC_CTX *mem_ctx, const char *ca_db,
                     bool wait_for_card, time_t timeout,
                     struct p11_ctx **p11_ctx);

errno_t init_verification(struct p11_ctx *p11_ctx,
                          struct cert_verify_opts *cert_verify_opts);

bool do_verification_b64(struct p11_ctx *p11_ctx, const char *cert_b64);

errno_t do_card(TALLOC_CTX *mem_ctx, struct p11_ctx *p11_ctx,
                enum op_mode mode, const char *pin,
                const char *module_name_in, const char *token_name_in,
                const char *key_id_in, const char *label,
                const char *uri, char **_multi);

errno_t parse_cert_verify_opts(TALLOC_CTX *mem_ctx, const char *verify_opts,
                               struct cert_verify_opts **cert_verify_opts);
#endif /* __P11_CHILD_H__ */
