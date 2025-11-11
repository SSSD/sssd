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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <popt.h>

#include "util/child_bootstrap.h"
#include "util/util.h"
#include "util/sss_prctl.h"
#include "providers/backend.h"
#include "util/crypto/sss_crypto.h"
#include "util/cert.h"
#include "util/sss_chain_id.h"
#include "p11_child/p11_child.h"

static const char *op_mode_str(enum op_mode mode)
{
    switch (mode) {
    case OP_NONE:
        return "none";
        break;
    case OP_AUTH:
        return "auth";
        break;
    case OP_PREAUTH:
        return "pre-auth";
        break;
    case OP_VERIFIY:
        return "verify";
        break;
    default:
        return "unknown";
    }
}

static int do_work(TALLOC_CTX *mem_ctx, enum op_mode mode, const char *ca_db,
                   struct cert_verify_opts *cert_verify_opts,
                   bool wait_for_card,
                   const char *cert_b64, const char *pin,
                   const char *module_name, const char *token_name,
                   const char *key_id, const char *label, const char *uri,
                   time_t timeout, char **multi)
{
    int ret;
    struct p11_ctx *p11_ctx;

    ret = init_p11_ctx(mem_ctx, ca_db, wait_for_card, timeout, &p11_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "init_p11_ctx failed.\n");
        return ret;
    }

    if (cert_verify_opts->do_verification) {
        ret = init_verification(p11_ctx, cert_verify_opts);
        if (ret != 0) {
            DEBUG(SSSDBG_OP_FAILURE, "init_verification failed.\n");
            goto done;
        }
    }


    if (mode == OP_VERIFIY) {
        if (!cert_verify_opts->do_verification
                    || do_verification_b64(p11_ctx, cert_b64)) {
            DEBUG(SSSDBG_TRACE_FUNC, "Certificate is valid.\n");
            ret = 0;
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, "Certificate is NOT valid.\n");
            ret = EINVAL;
        }
    } else {
        ret = do_card(mem_ctx, p11_ctx, mode, pin,
                      module_name, token_name, key_id, label, uri, multi);
    }

done:
    talloc_free(p11_ctx);

    return ret;
}

static errno_t p11c_recv_data(TALLOC_CTX *mem_ctx, int fd, char **pin)
{
    static const size_t IN_BUF_SIZE = 2048;
    uint8_t buf[IN_BUF_SIZE];
    ssize_t len;
    errno_t ret;
    char *str;

    errno = 0;
    len = sss_atomic_read_s(fd, buf, IN_BUF_SIZE);
    if (len == -1) {
        ret = errno;
        ret = (ret == 0) ? EINVAL: ret;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "read failed [%d][%s].\n", ret, strerror(ret));
        return ret;
    }

    if (len == 0 || *buf == '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing PIN.\n");
        return EINVAL;
    }

    str = talloc_strndup(mem_ctx, (char *) buf, len);
    if (str == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strndup failed.\n");
        return ENOMEM;
    }

    if (strlen(str) != len) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Input contains additional data, only PIN expected.\n");
        talloc_free(str);
        return EINVAL;
    }

    *pin = str;

    return EOK;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    errno_t ret = 0;
    TALLOC_CTX *main_ctx = NULL;
    enum op_mode mode = OP_NONE;
    enum pin_mode pin_mode = PIN_NONE;
    char *pin = NULL;
    char *ca_db = NULL;
    struct cert_verify_opts *cert_verify_opts;
    char *verify_opts = NULL;
    char *multi = NULL;
    char *module_name = NULL;
    char *token_name = NULL;
    char *key_id = NULL;
    char *label = NULL;
    char *cert_b64 = NULL;
    long timeout = -1;
    bool wait_for_card = false;
    char *uri = NULL;

    struct poptOption long_options[] = {
        SSSD_BASIC_CHILD_OPTS
        {"auth", 0, POPT_ARG_NONE, NULL, 'a', _("Run in auth mode"), NULL},
        {"pre", 0, POPT_ARG_NONE, NULL, 'p', _("Run in pre-auth mode"), NULL},
        {"wait_for_card", 0, POPT_ARG_NONE, NULL, 'w', _("Wait until card is available"), NULL},
        {"verification", 0, POPT_ARG_NONE, NULL, 'v', _("Run in verification mode"),
         NULL},
        {"pin", 0, POPT_ARG_NONE, NULL, 'i', _("Expect PIN on stdin"), NULL},
        {"keypad", 0, POPT_ARG_NONE, NULL, 'k', _("Expect PIN on keypad"),
         NULL},
        {"verify", 0, POPT_ARG_STRING, &verify_opts, 0 , _("Tune validation"),
         NULL},
        {"ca_db", 0, POPT_ARG_STRING, &ca_db, 0, _("CA DB to use"),
         NULL},
        {"module_name", 0, POPT_ARG_STRING, &module_name, 0,
         _("Module name for authentication"), NULL},
        {"token_name", 0, POPT_ARG_STRING, &token_name, 0,
         _("Token name for authentication"), NULL},
        {"key_id", 0, POPT_ARG_STRING, &key_id, 0,
         _("Key ID for authentication"), NULL},
        {"label", 0, POPT_ARG_STRING, &label, 0,
         _("Label for authentication"), NULL},
        {"certificate", 0, POPT_ARG_STRING, &cert_b64, 0,
         _("certificate to verify, base64 encoded"), NULL},
        {"uri", 0, POPT_ARG_STRING, &uri, 0,
         _("PKCS#11 URI to restrict selection"), NULL},
        {"timeout", 0, POPT_ARG_LONG, &timeout,
         0, _("OCSP communication timeout"), NULL},
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    /*
     * This child can run as root or as sssd user relying on policy kit to
     * grant access to pcscd. This means that no setuid or setgid bit must be
     * set on the binary. We still should make sure to run with a restrictive
     * umask but do not have to make additional precautions like clearing the
     * environment. This would allow to use e.g. pkcs11-spy.so for further
     * debugging.
     */
    umask(SSS_DFL_UMASK);

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while ((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        case 'a':
            if (mode != OP_NONE) {
                fprintf(stderr,
                        "\n--verify, --auth and --pre are mutually " \
                        "exclusive and should be only used once.\n\n");
                poptPrintUsage(pc, stderr, 0);
                _exit(-1);
            }
            mode = OP_AUTH;
            break;
        case 'p':
            if (mode != OP_NONE) {
                fprintf(stderr,
                        "\n--verify, --auth and --pre are mutually " \
                        "exclusive and should be only used once.\n\n");
                poptPrintUsage(pc, stderr, 0);
                _exit(-1);
            }
            mode = OP_PREAUTH;
            break;
        case 'v':
            if (mode != OP_NONE) {
                fprintf(stderr,
                        "\n--verify, --auth and --pre are mutually " \
                        "exclusive and should be only used once.\n\n");
                poptPrintUsage(pc, stderr, 0);
                _exit(-1);
            }
            mode = OP_VERIFIY;
            break;
        case 'i':
            if (pin_mode != PIN_NONE) {
                fprintf(stderr, "\n--pin and --keypad are mutually exclusive " \
                                "and should be only used once.\n\n");
                poptPrintUsage(pc, stderr, 0);
                _exit(-1);
            }
            pin_mode = PIN_STDIN;
            break;
        case 'k':
            if (pin_mode != PIN_NONE) {
                fprintf(stderr, "\n--pin and --keypad are mutually exclusive " \
                                "and should be only used once.\n\n");
                poptPrintUsage(pc, stderr, 0);
                _exit(-1);
            }
            pin_mode = PIN_KEYPAD;
            break;
        case 'w':
            wait_for_card = true;
            break;
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                  poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            _exit(-1);
        }
    }

    if (ca_db == NULL) {
        fprintf(stderr, "\nMissing CA DB path: --ca_db must be specified.\n\n");
        poptPrintUsage(pc, stderr, 0);
        _exit(-1);
    }

    if (mode == OP_NONE) {
        fprintf(stderr, "\nMissing operation mode, either " \
                        "--verify, --auth or --pre must be specified.\n\n");
        poptPrintUsage(pc, stderr, 0);
        _exit(-1);
    } else if (mode == OP_AUTH && pin_mode == PIN_NONE) {
        fprintf(stderr, "\nMissing PIN mode for authentication, " \
                        "either --pin or --keypad must be specified.\n");
        poptPrintUsage(pc, stderr, 0);
        _exit(-1);
    } else if (mode == OP_VERIFIY && cert_b64 == NULL) {
        fprintf(stderr, "\nMissing certificate for verify operation, " \
                        "--certificate base64_encoded_certificate " \
                        "must be added.\n");
        poptPrintUsage(pc, stderr, 0);
        _exit(-1);
    }

    poptFreeContext(pc);

    sss_child_basic_settings.name = "p11_child";
    sss_child_basic_settings.is_responder_invoked = true;
    if (!sss_child_setup_basics(&sss_child_basic_settings)) {
        _exit(-1);
    }

    DEBUG(SSSDBG_TRACE_FUNC, "p11_child started.\n");

    DEBUG(SSSDBG_TRACE_INTERNAL, "Running in [%s] mode.\n", op_mode_str(mode));

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Running with effective IDs: [%"SPRIuid"][%"SPRIgid"].\n",
          geteuid(), getegid());

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Running with real IDs [%"SPRIuid"][%"SPRIgid"].\n",
          getuid(), getgid());

    main_ctx = talloc_new(NULL);
    if (main_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed.\n");
        talloc_free(discard_const(debug_prg_name));
        ret = ENOMEM;
        goto done;
    }
    talloc_steal(main_ctx, debug_prg_name);

    /* We do not require the label, but it is recommended */
    if (mode == OP_AUTH && (module_name == NULL || token_name == NULL
                                || key_id == NULL)) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "--module_name, --token_name and --key_id must be given for "
              "authentication\n");
        ret = EINVAL;
        goto done;
    }

    ret = parse_cert_verify_opts(main_ctx, verify_opts, &cert_verify_opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to parse verify option.\n");
        ret = EINVAL;
        goto done;
    }

    if (mode == OP_VERIFIY && !cert_verify_opts->do_verification) {
        fprintf(stderr,
                "Called verification with option 'no_verification', "
                "it this intended?\n");
    }

    if (mode == OP_AUTH && pin_mode == PIN_STDIN) {
        ret = p11c_recv_data(main_ctx, STDIN_FILENO, &pin);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Failed to read PIN.\n");
            ret = EINVAL;
            goto done;
        }
    }

    /* sanity check for timeout value */
    if (timeout > INT32_MAX) {
        fprintf(stderr,
                "Timeout value [%li] is too long, using [%d]\n",
                timeout, INT32_MAX);
        timeout = INT32_MAX;
    } else if (timeout < -1) {
        timeout = -1;
    }

    ret = do_work(main_ctx, mode, ca_db, cert_verify_opts, wait_for_card,
                  cert_b64, pin, module_name, token_name, key_id, label, uri,
                  timeout, &multi);

done:
    fprintf(stdout, "%d\n%s", ret, multi ? multi : "");

    talloc_free(main_ctx);

    if (ret == EOK) {
        return EXIT_SUCCESS;
    } else if (ret == ERR_CA_DB_NOT_FOUND) {
        DEBUG(SSSDBG_CRIT_FAILURE, "p11_child failed - CA DB not found\n");
        return CA_DB_NOT_FOUND_EXIT_CODE;
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "p11_child failed (%d)\n", ret);
        return EXIT_FAILURE;
    }
}
