/*
   SSSD

   libcurl tevent integration test tool

   Copyright (C) Red Hat, 2016

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

#include <popt.h>

#include "util/util.h"
#include "util/tev_curl.h"

#define MAXREQ 64

struct tool_ctx {
    bool verbose;
    bool done;

    size_t nreqs;
};

struct tool_options {
    int debug;
    int verbose;
    int raw;
    int tls;
    int verify_peer;
    int verify_host;
    const char **headers;

    enum tcurl_http_method method;
    const char *socket_path;
    const char *capath;
    const char *cacert;

    const char *clientcert;
    const char *clientkey;

    const char *username;
    const char *password;
};

static void request_done(struct tevent_req *req)
{
    struct tool_ctx *tool_ctx;
    struct sss_iobuf *outbuf;
    int http_code;
    errno_t ret;

    tool_ctx = tevent_req_callback_data(req, struct tool_ctx);

    ret = tcurl_request_recv(tool_ctx, req, &outbuf, &http_code);
    talloc_zfree(req);

    tool_ctx->nreqs--;
    if (tool_ctx->nreqs == 0) {
        tool_ctx->done = true;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "HTTP request failed [%d]: %s\n",
              ret, sss_strerror(ret));
        return;
    } else if (tool_ctx->verbose) {
        printf("Request HTTP code: %d\n", http_code);
        printf("Request HTTP body: \n%s\n",
               (const char *) sss_iobuf_get_data(outbuf));
        talloc_zfree(outbuf);
    }
}

static errno_t
parse_options(poptContext pc, struct tool_options *opts)
{
    int opt;

    while ((opt = poptGetNextOpt(pc)) > 0) {
        switch (opt) {
        case 'g':
            opts->method = TCURL_HTTP_GET;
            break;
        case 'p':
            opts->method = TCURL_HTTP_PUT;
            break;
        case 'o':
            opts->method = TCURL_HTTP_POST;
            break;
        case 'd':
            opts->method = TCURL_HTTP_DELETE;
            break;
        default:
            DEBUG(SSSDBG_FATAL_FAILURE, "Unexpected option\n");
            return EINVAL;
        }
    }

    if (opt != -1) {
        poptPrintUsage(pc, stderr, 0);
        fprintf(stderr, "%s", poptStrerror(opt));
        return EINVAL;
    }

    return EOK;
}

static errno_t
prepare_requests(TALLOC_CTX *mem_ctx,
                 poptContext pc,
                 struct tool_options *opts,
                 struct tcurl_request ***_requests,
                 size_t *_num_requests)
{
    struct tcurl_request **requests;
    struct sss_iobuf *body;
    const char **headers;
    const char *arg;
    const char *url;
    errno_t ret;
    size_t i;

    static const char *default_headers[] = {
        "Content-type: application/octet-stream",
        NULL,
    };

    requests = talloc_zero_array(mem_ctx, struct tcurl_request *, MAXREQ + 1);
    if (requests == NULL) {
        return ENOMEM;
    }

    headers = opts->headers == NULL ? default_headers : opts->headers;

    i = 0;
    while ((arg = poptGetArg(pc)) != NULL) {
        if (i >= MAXREQ) {
            fprintf(stderr, _("Too many requests!\n"));
            ret = EINVAL;
            goto done;
        }

        switch (opts->method) {
        case TCURL_HTTP_GET:
        case TCURL_HTTP_DELETE:
            url = arg;
            body = NULL;
            break;
        case TCURL_HTTP_PUT:
        case TCURL_HTTP_POST:
            url = arg;

            arg = poptGetArg(pc);
            if (arg == NULL) {
                body = NULL;
                break;
            }

            body = sss_iobuf_init_readonly(requests,
                                           discard_const_p(uint8_t, arg),
                                           strlen(arg));
            if (body == NULL) {
                ret = ENOMEM;
                goto done;
            }
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Invalid method!\n");
            ret = EINVAL;
            goto done;
        }

        requests[i] = tcurl_http(requests, opts->method, opts->socket_path,
                                 url, headers, body);
        if (requests[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }

        if (opts->raw) {
            ret = tcurl_req_enable_rawoutput(requests[i]);
            if (ret != EOK) {
                goto done;
            }
        }

        if (opts->tls) {
            ret = tcurl_req_verify_peer(requests[i], opts->capath, opts->cacert,
                                        opts->verify_peer, opts->verify_host);
            if (ret != EOK) {
                goto done;
            }
        }

        if (opts->clientcert != NULL) {
            ret = tcurl_req_set_client_cert(requests[i], opts->clientcert,
                                            opts->clientkey);
            if (ret != EOK) {
                goto done;
            }
        }

        if (opts->username != NULL && opts->password != NULL) {
            ret = tcurl_req_http_basic_auth(requests[i], opts->username,
                                            opts->password);
            if (ret != EOK) {
                goto done;
            }
        }

        i++;
    }

    *_requests = requests;
    *_num_requests = i;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(requests);
    }

    return ret;
}

static errno_t
run_requests(struct tool_ctx *tool_ctx,
             struct tcurl_request **requests)
{
    TALLOC_CTX *tmp_ctx;
    struct tcurl_ctx *tcurl_ctx;
    struct tevent_context *ev;
    struct tevent_req *req;
    errno_t ret;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    if (requests == NULL || requests[0] == NULL) {
        ret = EOK;
        goto done;
    }

    ev = tevent_context_init(tmp_ctx);
    if (ev == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not init tevent context\n");
        ret = ENOMEM;
        goto done;
    }

    tcurl_ctx = tcurl_init(tmp_ctx, ev);
    if (tcurl_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not init tcurl context\n");
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; requests[i] != NULL; i++) {
        req = tcurl_request_send(tmp_ctx, ev, tcurl_ctx, requests[i], 5);
        if (req == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Could not create tevent request\n");
            ret = ENOMEM;
            goto done;
        }

        tevent_req_set_callback(req, request_done, tool_ctx);
    }

    while (tool_ctx->done == false) {
        tevent_loop_once(ev);
    }

    if (tool_ctx->nreqs > 0) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "The tool finished with some pending requests, fail!\n");
        ret = EEXIST;
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int main(int argc, const char *argv[])
{
    struct tool_options opts = { 0 };
    struct tool_ctx *tool_ctx;
    struct tcurl_request **requests;
    poptContext pc;
    errno_t ret;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT, &opts.debug, 0, "The debug level to run with", NULL },
        { "socket-path", 's', POPT_ARG_STRING, &opts.socket_path, 0, "The path to the HTTP server socket", NULL },
        { "get", 'g', POPT_ARG_NONE, NULL, 'g', "Perform a HTTP GET (default)", NULL },
        { "put", 'p', POPT_ARG_NONE, NULL, 'p', "Perform a HTTP PUT", NULL },
        { "post", 'o', POPT_ARG_NONE, NULL, 'o', "Perform a HTTP POST", NULL },
        { "del", 'd', POPT_ARG_NONE, NULL, 'd', "Perform a HTTP DELETE", NULL },
#ifdef POPT_ARG_ARGV
        { "header", 'h', POPT_ARG_ARGV, &opts.headers, '\0', "Add HTTP header", NULL },
#endif
        { "raw", 'r', POPT_ARG_NONE, &opts.raw, '\0', "Print raw protocol output", NULL },
        { "verbose", 'v', POPT_ARG_NONE, &opts.verbose, '\0', "Print response code and body", NULL },
        /* TLS */
        { "tls", '\0', POPT_ARG_NONE, &opts.tls, '\0', "Enable TLS", NULL },
        { "verify-peer", '\0', POPT_ARG_NONE, &opts.verify_peer, '\0', "Verify peer when TLS is enabled", NULL },
        { "verify-host", '\0', POPT_ARG_NONE, &opts.verify_host, '\0', "Verify host when TLS is enabled", NULL },
        { "capath", '\0', POPT_ARG_STRING, &opts.capath, '\0', "Path to CA directory where peer certificate is stored", NULL },
        { "cacert", '\0', POPT_ARG_STRING, &opts.cacert, '\0', "Path to CA certificate", NULL },
        { "clientcert", '\0', POPT_ARG_STRING, &opts.clientcert, '\0', "Path to client's certificate", NULL },
        { "clientkey", '\0', POPT_ARG_STRING, &opts.clientkey, '\0', "Path to client's private key", NULL },
        /* BASIC AUTH */
        { "username", '\0', POPT_ARG_STRING, &opts.username, '\0', "Username for basic authentication", NULL },
        { "password", '\0', POPT_ARG_STRING, &opts.password, '\0', "Password for basic authentication", NULL },
        POPT_TABLEEND
    };

    pc = poptGetContext(NULL, argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "[URL HTTPDATA]*");

    tool_ctx = talloc_zero(NULL, struct tool_ctx);
    if (tool_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not init tool context\n");
        ret = ENOMEM;
        goto done;
    }

    ret = parse_options(pc, &opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to parse options [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    DEBUG_CLI_INIT(opts.debug);
    tool_ctx->verbose = opts.verbose;

    ret = prepare_requests(tool_ctx, pc, &opts, &requests, &tool_ctx->nreqs);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to prepare requests [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = run_requests(tool_ctx, requests);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to issue requests [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

done:
    talloc_free(tool_ctx);
    poptFreeContext(pc);

    if (ret != EOK) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
