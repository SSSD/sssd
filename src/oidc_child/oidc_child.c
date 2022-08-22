/*
    SSSD

    Helper child for OIDC and OAuth 2.0 Device Authorization Grant

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2022 Red Hat

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

#include "oidc_child/oidc_child_util.h"

#include "util/util.h"
#include "util/atomic_io.h"

#define IN_BUF_SIZE 4096
static errno_t read_from_stdin(TALLOC_CTX *mem_ctx, char **out)
{
    uint8_t buf[IN_BUF_SIZE];
    ssize_t len;
    errno_t ret;
    char *str;

    errno = 0;
    len = sss_atomic_read_s(STDIN_FILENO, buf, IN_BUF_SIZE);
    if (len == -1) {
        ret = errno;
        ret = (ret == 0) ? EINVAL: ret;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "read failed [%d][%s].\n", ret, strerror(ret));
        return ret;
    }

    if (len == 0 || *buf == '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing device code\n");
        return EINVAL;
    }

    str = talloc_strndup(mem_ctx, (char *) buf, len);
    sss_erase_mem_securely(buf, IN_BUF_SIZE);
    if (str == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strndup failed.\n");
        return ENOMEM;
    }
    talloc_set_destructor((void *) str, sss_erase_talloc_mem_securely);

    if (strlen(str) != len) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Input contains additional data.\n");
        talloc_free(str);
        return EINVAL;
    }

    *out = str;

    return EOK;
}

static errno_t read_device_code_from_stdin(struct devicecode_ctx *dc_ctx,
                                           const char **out)
{
    char *str;
    errno_t ret;
    char *sep;

    ret = read_from_stdin(dc_ctx, &str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "read_from_stdin failed.\n");
        return ret;
    }

    if (out != NULL) {
        /* expect the client secret in the first line */
        sep = strchr(str, '\n');
        if (sep == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Format error, expecting client secret and JSON data.\n");
            talloc_free(str);
            return EINVAL;
        }
        *sep = '\0';
        *out = str;
        sep++;
    } else {
        sep = str;
    }

    clean_http_data(dc_ctx);
    dc_ctx->http_data = talloc_strdup(dc_ctx, sep);

    DEBUG(SSSDBG_TRACE_ALL, "JSON device code: [%s].\n", dc_ctx->http_data);

    return EOK;
}

static errno_t read_client_secret_from_stdin(struct devicecode_ctx *dc_ctx,
                                             const char **out)
{
    char *str;
    errno_t ret;

    ret = read_from_stdin(dc_ctx, &str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "read_from_stdin failed.\n");
        return ret;
    }

    *out = str;

    DEBUG(SSSDBG_TRACE_ALL, "Client secret: [%s].\n", *out);

    return EOK;
}

static errno_t set_endpoints(struct devicecode_ctx *dc_ctx,
                             const char *device_auth_endpoint,
                             const char *token_endpoint,
                             const char *userinfo_endpoint,
                             const char *jwks_uri,
                             const char *scope)
{
    int ret;

    dc_ctx->device_authorization_endpoint = talloc_strdup(dc_ctx,
                                                          device_auth_endpoint);
    if (dc_ctx->device_authorization_endpoint == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing device_authorization_endpoint.\n");
        ret = EINVAL;
        goto done;
    }
    dc_ctx->token_endpoint = talloc_strdup(dc_ctx, token_endpoint);
    if (dc_ctx->token_endpoint == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing token_endpoint.\n");
        ret = EINVAL;
        goto done;
    }
    dc_ctx->userinfo_endpoint = talloc_strdup(dc_ctx, userinfo_endpoint);
    if (dc_ctx->userinfo_endpoint == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing userinfo_endpoint.\n");
        ret = EINVAL;
        goto done;
    }

    if (jwks_uri != NULL && *jwks_uri != '\0') {
        dc_ctx->jwks_uri = talloc_strdup(dc_ctx, jwks_uri);
        if (dc_ctx->jwks_uri == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to copy jwks_uri.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    if (scope != NULL && *scope != '\0') {
        dc_ctx->scope = url_encode_string(dc_ctx, scope);
        if (dc_ctx->scope == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to encode and copy scopes.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    ret = EOK;
done:
    return ret;
}

static struct devicecode_ctx *get_dc_ctx(TALLOC_CTX *mem_ctx,
                                         bool libcurl_debug, const char *ca_db,
                                         const char *issuer_url,
                                         const char *device_auth_endpoint,
                                         const char *token_endpoint,
                                         const char *userinfo_endpoint,
                                         const char *jwks_uri, const char *scope)
{
    struct devicecode_ctx *dc_ctx = NULL;
    int ret;

    dc_ctx = talloc_zero(mem_ctx, struct devicecode_ctx);
    if (dc_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to allocate memory for results.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = init_curl(dc_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to init libcurl.\n");
        goto done;
    }

    dc_ctx->libcurl_debug = libcurl_debug;

    if (ca_db != NULL) {
        dc_ctx->ca_db = talloc_strdup(dc_ctx, ca_db);
        if (dc_ctx->ca_db == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy CA DB path.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    if (issuer_url != NULL) {
        ret = get_openid_configuration(dc_ctx, issuer_url);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get openid configuration.\n");
            goto done;
        }

        ret = parse_openid_configuration(dc_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to parse openid configuration.\n");
            goto done;
        }
    } else if (device_auth_endpoint != NULL && token_endpoint != NULL) {
        ret = set_endpoints(dc_ctx, device_auth_endpoint, token_endpoint,
                            userinfo_endpoint, jwks_uri, scope);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to set endpoints.\n");
            goto done;
        }
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing issuer information.\n");
        ret = EINVAL;
        goto done;
    }

done:
    if (ret != EOK) {
        talloc_free(dc_ctx);
        dc_ctx = NULL;
    }
    return dc_ctx;
}

struct cli_opts {
    const char *opt_logger;
    const char *issuer_url;
    const char *client_id;
    const char *device_auth_endpoint;
    const char *token_endpoint;
    const char *userinfo_endpoint;
    const char *jwks_uri;
    const char *scope;
    const char *client_secret;
    bool client_secret_stdin;
    const char *ca_db;
    const char *user_identifier_attr;
    bool libcurl_debug;
    bool get_device_code;
    bool get_access_token;
};

static int parse_cli(int argc, const char *argv[], struct cli_opts *opts)
{
    poptContext pc;
    int opt;
    errno_t ret;
    int debug_fd = -1;
    const char *opt_logger = NULL;
    bool print_usage = true;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"debug-fd", 0, POPT_ARG_INT, &debug_fd, 0,
         _("An open file descriptor for the debug logs"), NULL},
        {"get-device-code", 0, POPT_ARG_NONE, NULL, 'a',
                _("Get device code and URL"), NULL},
        {"get-access-token", 0, POPT_ARG_NONE, NULL, 'b',
                _("Wait for access token"), NULL},
        {"issuer-url", 0, POPT_ARG_STRING, &opts->issuer_url, 0,
                _("URL of Issuer IdP"), NULL},
        {"device-auth-endpoint", 0, POPT_ARG_STRING, &opts->device_auth_endpoint, 0,
                _("Device authorization endpoint of the IdP"), NULL},
        {"token-endpoint", 0, POPT_ARG_STRING, &opts->token_endpoint, 0,
                _("Token endpoint of the IdP"), NULL},
        {"userinfo-endpoint", 0, POPT_ARG_STRING, &opts->userinfo_endpoint, 0,
                _("Userinfo endpoint of the IdP"), NULL},
        {"user-identifier-attribute", 0, POPT_ARG_STRING,
                &opts->user_identifier_attr, 0,
                _("Unique identifier of the user in the userinfo data"), NULL},
        {"jwks-uri", 0, POPT_ARG_STRING, &opts->jwks_uri, 0,
                _("JWKS URI of the IdP"), NULL},
        {"scope", 0, POPT_ARG_STRING, &opts->scope, 0,
                _("Supported scope of the IdP to get userinfo"), NULL},
        {"client-id", 0, POPT_ARG_STRING, &opts->client_id, 0, _("Client ID"), NULL},
        {"client-secret", 0, POPT_ARG_STRING, &opts->client_secret, 0,
                _("Client secret (if needed)"), NULL},
        {"client-secret-stdin", 0, POPT_ARG_NONE, NULL, 's',
                _("Read client secret from standard input"), NULL},
        {"ca-db", 0, POPT_ARG_STRING, &opts->ca_db, 0,
                _("Path to PEM file with CA certificates"), NULL},
        {"libcurl-debug", 0, POPT_ARG_NONE, NULL, 'c',
                _("Enable libcurl debug output"), NULL},
        SSSD_LOGGER_OPTS
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    umask(SSS_DFL_UMASK);

    ret = EINVAL; /* assume issue with command line arguments */

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while ((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        case 'a':
            opts->get_device_code = true;
            break;
        case 'b':
            opts->get_access_token = true;
            break;
        case 'c':
            opts->libcurl_debug = true;
            break;
        case 's':
            opts->client_secret_stdin = true;
            break;
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                  poptBadOption(pc, 0), poptStrerror(opt));
            goto done;
        }
    }

    if (!opts->get_device_code && !opts->get_access_token) {
        fprintf(stderr,
                "\n--get-device-code or --get-access-token must be given.\n\n");
        goto done;
    }

    if (opts->get_device_code && opts->get_access_token) {
        fprintf(stderr,
                "\n--get-device-code and --get-access-token "
                "are mutually exclusive .\n\n");
        goto done;
    }

    if ((opts->issuer_url != NULL
                && (opts->device_auth_endpoint != NULL
                        || opts->token_endpoint != NULL))
        || (opts->device_auth_endpoint != NULL && opts->token_endpoint != NULL
                           && opts->issuer_url != NULL)
        || (opts->issuer_url == NULL
                && ((opts->device_auth_endpoint != NULL
                        && opts->token_endpoint == NULL)
                   || (opts->device_auth_endpoint == NULL
                        && opts->token_endpoint != NULL)))
        || (opts->issuer_url == NULL
                && (opts->device_auth_endpoint == NULL
                        || opts->token_endpoint == NULL))) {
        fprintf(stderr, "\n--issuer-url or --device-auth-endpoint "
                        "together with --token-endpoint are mutually exclusive "
                        "but one variant must be given.\n\n");
        goto done;
    }

    if (opts->client_id == NULL) {
        fprintf(stderr, "\n--client-id must be given.\n\n");
        goto done;
    }

    if (opts->client_secret != NULL && opts->client_secret_stdin) {
        fprintf(stderr, "\n--client-secret and --client-secret-stdin are "
                        "mutually exclusive.\n\n");
        goto done;
    }

    poptFreeContext(pc);
    print_usage = false;

    debug_prg_name = talloc_asprintf(NULL, "oidc_child[%d]", getpid());
    if (debug_prg_name == NULL) {
        ERROR("talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    opts->opt_logger = opt_logger;

    if (debug_fd != -1) {
        opts->opt_logger = sss_logger_str[FILES_LOGGER];
        ret = set_debug_file_from_fd(debug_fd);
        if (ret != EOK) {
            opts->opt_logger = sss_logger_str[STDERR_LOGGER];
            ERROR("set_debug_file_from_fd failed.\n");
            return ret;
        }
    }

    ret = EOK;

done:
    if (print_usage) {
        poptPrintUsage(pc, stderr, 0);
        poptFreeContext(pc);
    }

    return ret;
}

void trace_device_code(struct devicecode_ctx *dc_ctx, bool get_device_code)
{
    if (!DEBUG_IS_SET(SSSDBG_TRACE_ALL)) {
        return;
    }

    if (get_device_code) {
        DEBUG(SSSDBG_TRACE_ALL, "user_code: [%s].\n", dc_ctx->user_code);
        DEBUG(SSSDBG_TRACE_ALL, "verification_uri: [%s].\n",
                                dc_ctx->verification_uri);
        DEBUG(SSSDBG_TRACE_ALL, "verification_uri_complete: [%s].\n",
                                dc_ctx->verification_uri_complete == NULL ? "-"
                                           : dc_ctx->verification_uri_complete);
        DEBUG(SSSDBG_TRACE_ALL, "message: [%s].\n", dc_ctx->message);
    }
    DEBUG(SSSDBG_TRACE_ALL, "device_code: [%s].\n", dc_ctx->device_code);
    DEBUG(SSSDBG_TRACE_ALL, "expires_in: [%d].\n", dc_ctx->expires_in);
    DEBUG(SSSDBG_TRACE_ALL, "interval: [%d].\n", dc_ctx->interval);
}

void trace_tokens(struct devicecode_ctx *dc_ctx)
{
    char *tmp;
    if (!DEBUG_IS_SET(SSSDBG_TRACE_ALL)) {
        return;
    }

    if (dc_ctx->td->access_token_payload != NULL) {
        tmp = json_dumps(dc_ctx->td->access_token_payload, 0);
        DEBUG(SSSDBG_TRACE_ALL, "access_token payload: [%s].\n", tmp);
        free(tmp);

        DEBUG(SSSDBG_TRACE_ALL, "User Principal: [%s].\n", json_string_value(json_object_get(dc_ctx->td->access_token_payload, "upn")));
        DEBUG(SSSDBG_TRACE_ALL, "User oid: [%s].\n", json_string_value(json_object_get(dc_ctx->td->access_token_payload, "oid")));
        DEBUG(SSSDBG_TRACE_ALL, "User sub: [%s].\n", json_string_value(json_object_get(dc_ctx->td->access_token_payload, "sub")));
    }

    if (dc_ctx->td->id_token_payload != NULL) {
        tmp = json_dumps(dc_ctx->td->id_token_payload, 0);
        DEBUG(SSSDBG_TRACE_ALL, "id_token payload: [%s].\n", tmp);
        free(tmp);

        DEBUG(SSSDBG_TRACE_ALL, "User Principal: [%s].\n", json_string_value(json_object_get(dc_ctx->td->id_token_payload, "upn")));
        DEBUG(SSSDBG_TRACE_ALL, "User oid: [%s].\n", json_string_value(json_object_get(dc_ctx->td->id_token_payload, "oid")));
        DEBUG(SSSDBG_TRACE_ALL, "User sub: [%s].\n", json_string_value(json_object_get(dc_ctx->td->id_token_payload, "sub")));
    }

    tmp = json_dumps(dc_ctx->td->userinfo, 0);
    DEBUG(SSSDBG_TRACE_ALL, "userinfo: [%s].\n", tmp);
    free(tmp);
}

int main(int argc, const char *argv[])
{
    struct cli_opts opts = { 0 };
    errno_t ret;
    json_error_t json_error;
    TALLOC_CTX *main_ctx = NULL;
    struct devicecode_ctx *dc_ctx;
    const char *user_identifier = NULL;
    int exit_status = EXIT_FAILURE;

    ret = parse_cli(argc, argv, &opts);
    if (ret != EOK) {
        goto done;
    }

    DEBUG_INIT(debug_level, opts.opt_logger);

    DEBUG(SSSDBG_TRACE_FUNC, "oidc_child started.\n");

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
        goto done;
    }
    talloc_steal(main_ctx, debug_prg_name);

    dc_ctx = get_dc_ctx(main_ctx, opts.libcurl_debug, opts.ca_db,
                        opts.issuer_url,
                        opts.device_auth_endpoint, opts.token_endpoint,
                        opts.userinfo_endpoint, opts.jwks_uri, opts.scope);
    if (dc_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to initialize main context.\n");
        goto done;
    }

    if (opts.get_device_code) {
        if (opts.client_secret_stdin) {
            ret = read_client_secret_from_stdin(dc_ctx, &opts.client_secret);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to read client secret from stdin.\n");
                goto done;
            }
        }

        ret = get_devicecode(dc_ctx, opts.client_id, opts.client_secret);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get device code.\n");
            goto done;
        }
    }

    if (opts.get_access_token) {
        if (dc_ctx->device_code == NULL) {
            ret = read_device_code_from_stdin(dc_ctx,
                                              opts.client_secret_stdin
                                                           ? &opts.client_secret
                                                           : NULL);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to read device code from stdin.\n");
                goto done;
            }
        }
    }

    ret = parse_result(dc_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to parse device code reply.\n");
        goto done;
    }

    trace_device_code(dc_ctx, opts.get_device_code);

    ret = get_token(main_ctx, dc_ctx, opts.client_id, opts.client_secret,
                    opts.get_device_code);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get user token.\n");
        goto done;
    }

    if (opts.get_device_code) {
        /* Currently this reply is used by ipa-otpd as RADIUS Proxy-State and
         * Reply-Message.
         */
        fprintf(stdout,
                "{\"device_code\":\"%s\",\"expires_in\":%d,\"interval\":%d}\n",
                dc_ctx->device_code, dc_ctx->expires_in, dc_ctx->interval);
        fprintf(stdout,
                "oauth2 {\"verification_uri\": \"%s\", "
                "\"user_code\": \"%s%s%s\"}\n",
                dc_ctx->verification_uri, dc_ctx->user_code,
                dc_ctx->verification_uri_complete == NULL ? ""
                                      : "\", \"verification_uri_complete\": \"",
                dc_ctx->verification_uri_complete == NULL ? ""
                                           : dc_ctx->verification_uri_complete);
        fflush(stdout);
    }

    if (opts.get_access_token) {
        DEBUG(SSSDBG_TRACE_ALL, "access_token: [%s].\n",
                                dc_ctx->td->access_token_str);
        DEBUG(SSSDBG_TRACE_ALL, "id_token: [%s].\n", dc_ctx->td->id_token_str);

        if (dc_ctx->jwks_uri != NULL) {
            ret = verify_token(dc_ctx);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Failed to verify tokens.\n");
                goto done;
            }
        }

        ret = get_userinfo(dc_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get userinfo.\n");
            goto done;
        }

        dc_ctx->td->userinfo = json_loads(dc_ctx->http_data, 0, &json_error);
        if (dc_ctx->td->userinfo == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to parse userinfo data on line [%d]: [%s].\n",
                  json_error.line, json_error.text);
            goto done;
        }

        trace_tokens(dc_ctx);

        user_identifier = get_user_identifier(dc_ctx, dc_ctx->td->userinfo,
                                              opts.user_identifier_attr);
        if (user_identifier == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to get user identifier.\n");
            goto done;
        }

        DEBUG(SSSDBG_CONF_SETTINGS, "User identifier: [%s].\n",
                                    user_identifier);

        fprintf(stdout,"%s", user_identifier);
        fflush(stdout);
    }

    DEBUG(SSSDBG_IMPORTANT_INFO, "oidc_child finished successful!\n");
    exit_status = EXIT_SUCCESS;

done:
    if (exit_status != EXIT_SUCCESS) {
        DEBUG(SSSDBG_IMPORTANT_INFO, "oidc_child failed!\n");
    }
    close(STDOUT_FILENO);
    talloc_free(main_ctx);
    return exit_status;
}
