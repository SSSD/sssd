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

    errno_t error;
    bool done;

    size_t nreqs;
};

static void request_done(struct tevent_req *req)
{
    int http_code;
    struct sss_iobuf *outbuf;
    struct tool_ctx *tool_ctx = tevent_req_callback_data(req,
                                                         struct tool_ctx);

    tool_ctx->error = tcurl_http_recv(tool_ctx, req,
                                      &http_code,
                                      &outbuf);
    talloc_zfree(req);

    if (tool_ctx->error != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "HTTP request failed: %d\n", tool_ctx->error);
        tool_ctx->done = true;
        return;
    } else if (tool_ctx->verbose) {
        printf("Request HTTP code: %d\n", http_code);
        printf("Request HTTP body: \n%s\n",
               (const char *) sss_iobuf_get_data(outbuf));
        talloc_zfree(outbuf);
    }

    tool_ctx->nreqs--;
    if (tool_ctx->nreqs == 0) {
        tool_ctx->done = true;
    }
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;

    int pc_debug = 0;
    int pc_verbose = 0;
    const char *socket_path = NULL;
    const char *extra_arg_ptr;

    static const char *headers[] = {
        "Content-type: application/octet-stream",
        NULL,
    };

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT, &pc_debug, 0,
          "The debug level to run with", NULL },
        { "socket-path", 's', POPT_ARG_STRING, &socket_path, 0,
          "The path to the HTTP server socket", NULL },
        { "get", 'g', POPT_ARG_NONE, NULL, 'g', "Perform a HTTP GET (default)", NULL },
        { "put", 'p', POPT_ARG_NONE, NULL, 'p', "Perform a HTTP PUT", NULL },
        { "del", 'd', POPT_ARG_NONE, NULL, 'd', "Perform a HTTP DELETE", NULL },
        { "verbose", 'v', POPT_ARG_NONE, NULL, 'v', "Print response code and body", NULL },
        POPT_TABLEEND
    };

    struct tevent_req *req;
    struct tevent_context *ev;
    enum tcurl_http_request req_type = TCURL_HTTP_GET;
    struct tcurl_ctx *ctx;
    struct tool_ctx *tool_ctx;

    const char *urls[MAXREQ] = { 0 };
    struct sss_iobuf **inbufs;

    size_t n_reqs = 0;

    debug_prg_name = argv[0];
    pc = poptGetContext(NULL, argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "HTTPDATA");

    while ((opt = poptGetNextOpt(pc)) > 0) {
        switch (opt) {
        case 'g':
            req_type = TCURL_HTTP_GET;
            break;
        case 'p':
            req_type = TCURL_HTTP_PUT;
            break;
        case 'd':
            req_type = TCURL_HTTP_DELETE;
            break;
        case 'v':
            pc_verbose = 1;
            break;
        default:
            DEBUG(SSSDBG_FATAL_FAILURE, "Unexpected option\n");
            return 1;
        }
    }

    DEBUG_CLI_INIT(pc_debug);

    tool_ctx = talloc_zero(NULL, struct tool_ctx);
    if (tool_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not init tool context\n");
        return 1;
    }

    inbufs = talloc_zero_array(tool_ctx, struct sss_iobuf *, MAXREQ);
    if (inbufs == NULL) {
        talloc_zfree(tool_ctx);
        return 1;
    }

    while ((extra_arg_ptr = poptGetArg(pc)) != NULL) {
        switch (req_type) {
        case TCURL_HTTP_GET:
        case TCURL_HTTP_DELETE:
            urls[n_reqs++] = extra_arg_ptr;
            break;
        case TCURL_HTTP_PUT:
            if (urls[n_reqs] == NULL) {
                urls[n_reqs] = extra_arg_ptr;
            } else {
                inbufs[n_reqs] = sss_iobuf_init_readonly(
                                              inbufs,
                                              (uint8_t *) discard_const(extra_arg_ptr),
                                              strlen(extra_arg_ptr));
                if (inbufs[n_reqs] == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "Could not init input buffer\n");
                    talloc_zfree(tool_ctx);
                    return 1;
                }
                n_reqs++;
            }
            break;
        }
    }

    if (opt != -1) {
        poptPrintUsage(pc, stderr, 0);
        fprintf(stderr, "%s", poptStrerror(opt));
        talloc_zfree(tool_ctx);
        return 1;
    }

    if (!socket_path) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Please specify the socket path\n");
        poptPrintUsage(pc, stderr, 0);
        talloc_zfree(tool_ctx);
        return 1;
    }

    tool_ctx->nreqs = n_reqs;
    tool_ctx->verbose = !!pc_verbose;

    ev = tevent_context_init(tool_ctx);
    if (ev == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not init tevent context\n");
        talloc_zfree(tool_ctx);
        return 1;
    }

    ctx = tcurl_init(tool_ctx, ev);
    if (ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not init tcurl context\n");
        talloc_zfree(tool_ctx);
        return 1;
    }

    for (size_t i = 0; i < n_reqs; i++) {
        req = tcurl_http_send(tool_ctx, ev, ctx,
                              req_type,
                              socket_path,
                              urls[i],
                              headers,
                              inbufs[i],
                              10);
        if (ctx == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE, "Could not create request\n");
            talloc_zfree(tool_ctx);
            return 1;
        }
        tevent_req_set_callback(req, request_done, tool_ctx);
    }

    while (tool_ctx->done == false) {
        tevent_loop_once(ev);
    }

    if (tool_ctx->nreqs > 0) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "The tool finished with some pending requests, fail!\n");
        talloc_zfree(tool_ctx);
        return 1;
    }

    talloc_free(tool_ctx);
    poptFreeContext(pc);
    return 0;
}
