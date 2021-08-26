/*
    SSSD

    Unit tests - exercise the krb5 child

    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include <stdio.h>
#include <stdlib.h>
#include <talloc.h>
#include <popt.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>

#include "util/util.h"

/* Interfaces being tested */
#include "providers/krb5/krb5_auth.h"
#include "providers/krb5/krb5_common.h"
#include "providers/krb5/krb5_utils.h"
#include "providers/krb5/krb5_ccache.h"

extern struct dp_option default_krb5_opts[];

static krb5_context krb5_error_ctx;
#define KRB5_CHILD_TEST_DEBUG(level, error) KRB5_DEBUG(level, krb5_error_ctx, error)

#define CHECK_KRET_L(kret, err, label) do {     \
    if (kret) {                                 \
        KRB5_CHILD_TEST_DEBUG(SSSDBG_OP_FAILURE, kret);    \
        goto label;                             \
    }                                           \
} while(0)                                      \

struct krb5_child_test_ctx {
    struct tevent_context *ev;
    struct krb5child_req *kr;

    bool done;
    errno_t child_ret;

    uint8_t *buf;
    ssize_t len;
    struct krb5_child_response *res;
};

static errno_t
setup_krb5_child_test(TALLOC_CTX *mem_ctx, struct krb5_child_test_ctx **_ctx)
{
    struct krb5_child_test_ctx *ctx;

    ctx = talloc_zero(mem_ctx, struct krb5_child_test_ctx);
    if (!ctx) return ENOMEM;

    ctx->ev = tevent_context_init(ctx);
    if (ctx->ev == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not init tevent context\n");
        talloc_free(ctx);
        return EFAULT;
    }

    *_ctx = ctx;
    return EOK;
}

static struct krb5_ctx *
create_dummy_krb5_ctx(TALLOC_CTX *mem_ctx, const char *realm)
{
    struct krb5_ctx *krb5_ctx;
    int i;
    errno_t ret;

    krb5_ctx = talloc_zero(mem_ctx, struct krb5_ctx);
    if (!krb5_ctx) return NULL;

    ret = sss_regexp_new(krb5_ctx, ILLEGAL_PATH_PATTERN, 0, &(krb5_ctx->illegal_path_re));
    if (ret != EOK) {
        goto fail;
    }

    /* Kerberos options */
    krb5_ctx->opts = talloc_zero_array(krb5_ctx, struct dp_option, KRB5_OPTS);
    if (!krb5_ctx->opts) goto fail;
    for (i = 0; i < KRB5_OPTS; i++) {
        krb5_ctx->opts[i].opt_name = default_krb5_opts[i].opt_name;
        krb5_ctx->opts[i].type = default_krb5_opts[i].type;
        krb5_ctx->opts[i].def_val = default_krb5_opts[i].def_val;
        switch (krb5_ctx->opts[i].type) {
            case DP_OPT_STRING:
                ret = dp_opt_set_string(krb5_ctx->opts, i,
                                        default_krb5_opts[i].def_val.string);
                break;
            case DP_OPT_BLOB:
                ret = dp_opt_set_blob(krb5_ctx->opts, i,
                                      default_krb5_opts[i].def_val.blob);
                break;
            case DP_OPT_NUMBER:
                ret = dp_opt_set_int(krb5_ctx->opts, i,
                                     default_krb5_opts[i].def_val.number);
                break;
            case DP_OPT_BOOL:
                ret = dp_opt_set_bool(krb5_ctx->opts, i,
                                      default_krb5_opts[i].def_val.boolean);
                break;
        }
        if (ret) goto fail;
    }

    ret = dp_opt_set_string(krb5_ctx->opts, KRB5_REALM, realm);
    if (ret) goto fail;

    return krb5_ctx;

fail:
    talloc_free(krb5_ctx);
    return NULL;
}

static struct pam_data *
create_dummy_pam_data(TALLOC_CTX *mem_ctx, const char *user,
                      const char *password)
{
    struct pam_data *pd;
    const char *authtok;
    size_t authtok_len;
    errno_t ret;

    pd = create_pam_data(mem_ctx);
    if (!pd) goto fail;

    pd->cmd = SSS_PAM_AUTHENTICATE;
    pd->user = talloc_strdup(pd, user);
    if (!pd->user) goto fail;

    ret = sss_authtok_set_password(pd->authtok, password, 0);
    if (ret) goto fail;

    (void)sss_authtok_get_password(pd->authtok, &authtok, &authtok_len);
    DEBUG(SSSDBG_FUNC_DATA, "Authtok [%s] len [%d]\n",
                             authtok, (int)authtok_len);

    return pd;

fail:
    talloc_free(pd);
    return NULL;
}

static struct krb5child_req *
create_dummy_req(TALLOC_CTX *mem_ctx, const char *user,
                 const char *password, const char *realm,
                 const char *ccname, const char *ccname_template,
                 int timeout)
{
    struct krb5child_req *kr;
    struct passwd *pwd;
    errno_t ret;

    /* The top level child request */
    kr = talloc_zero(mem_ctx, struct krb5child_req);
    if (!kr) return NULL;

    pwd = getpwnam(user);
    if (!pwd) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Cannot get info on user [%s]\n", user);
        goto fail;
    }

    kr->uid = pwd->pw_uid;
    kr->gid = pwd->pw_gid;

    /* The Kerberos context */
    kr->krb5_ctx = create_dummy_krb5_ctx(kr, realm);
    if (!kr->krb5_ctx) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to create dummy krb5_ctx\n");
        goto fail;
    }
    /* PAM Data structure */
    kr->pd = create_dummy_pam_data(kr, user, password);
    if (!kr->pd) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to create dummy pam_data");
        goto fail;
    }

    ret = krb5_get_simple_upn(kr, kr->krb5_ctx, NULL, kr->pd->user, NULL,
                              &kr->upn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "krb5_get_simple_upn failed.\n");
        goto fail;
    }

    /* Override options with what was provided by the user */
    if (ccname_template) {
        ret = dp_opt_set_string(kr->krb5_ctx->opts, KRB5_CCNAME_TMPL,
                                ccname_template);
        if (ret != EOK) goto fail;
    }

    if (timeout) {
        ret = dp_opt_set_int(kr->krb5_ctx->opts, KRB5_AUTH_TIMEOUT, timeout);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to set value for krb5_auth_timeout\n");
            goto fail;
        }
    }

    if (!ccname) {
        kr->ccname = expand_ccname_template(kr, kr,
                                        dp_opt_get_cstring(kr->krb5_ctx->opts,
                                                           KRB5_CCNAME_TMPL),
                                            kr->krb5_ctx->illegal_path_re, true, true);
        if (!kr->ccname) goto fail;

        DEBUG(SSSDBG_FUNC_DATA, "ccname [%s] uid [%llu] gid [%llu]\n",
              kr->ccname, (unsigned long long) kr->uid,
              (unsigned long long) kr->gid);
    } else {
        kr->ccname = talloc_strdup(kr, ccname);
    }
    if (!kr->ccname) goto fail;

    DEBUG(SSSDBG_FUNC_DATA, "ccname [%s] uid [%u] gid [%u]\n",
            kr->ccname, kr->uid, kr->gid);

    ret = sss_krb5_precreate_ccache(kr->ccname,
                                    kr->uid, kr->gid);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "create_ccache_dir failed.\n");
        goto fail;
    }

    return kr;

fail:
    talloc_free(kr);
    return NULL;
}

static void
child_done(struct tevent_req *req)
{
    struct krb5_child_test_ctx *ctx = tevent_req_callback_data(req,
                                    struct krb5_child_test_ctx);
    errno_t ret;

    ret = handle_child_recv(req, ctx, &ctx->buf, &ctx->len);
    talloc_free(req);
    ctx->done = true;
    ctx->child_ret = ret;
}

static void
printtime(krb5_timestamp ts)
{
    krb5_error_code kret;
    char timestring[BUFSIZ];
    char fill = '\0';

#ifdef HAVE_KRB5_TIMESTAMP_TO_SFSTRING
    kret = krb5_timestamp_to_sfstring(ts, timestring, BUFSIZ, &fill);
    if (kret) {
        KRB5_CHILD_TEST_DEBUG(SSSDBG_OP_FAILURE, kret);
    }
    printf("%s", timestring);
#else
    printf("%s", ctime(&ts));
#endif /* HAVE_KRB5_TIMESTAMP_TO_SFSTRING */
}

static void
print_creds(krb5_context kcontext, krb5_creds *cred, const char *defname)
{
    krb5_error_code kret;
    char *name = NULL;
    char *sname = NULL;

    kret = krb5_unparse_name(kcontext, cred->client, &name);
    CHECK_KRET_L(kret, EIO, done);

    kret = krb5_unparse_name(kcontext, cred->server, &sname);
    CHECK_KRET_L(kret, EIO, done);

    if (!cred->times.starttime) {
        cred->times.starttime = cred->times.authtime;
    }


    printf("\t\t%s\n", sname);
    printf("\t\tValid from\t");  printtime(cred->times.starttime);
    printf("\n\t\tValid until\t"); printtime(cred->times.endtime);
    printf("\n");

    if (strcmp(name, defname)) {
        printf("\t\tfor client %s", name);
    }

done:
    krb5_free_unparsed_name(kcontext, name);
    krb5_free_unparsed_name(kcontext, sname);
}

static errno_t
print_ccache(const char *cc)
{
    krb5_cc_cursor cur;
    krb5_ccache cache = NULL;
    krb5_error_code kret;
    krb5_context kcontext = NULL;
    krb5_principal_data *princ = NULL;
    krb5_creds creds;
    char *defname = NULL;
    int i = 1;
    errno_t ret = EIO;

    kret = krb5_init_context(&kcontext);
    CHECK_KRET_L(kret, EIO, done);

    kret = krb5_cc_resolve(kcontext, cc, &cache);
    CHECK_KRET_L(kret, EIO, done);

    kret = krb5_cc_get_principal(kcontext, cache, &princ);
    CHECK_KRET_L(kret, EIO, done);

    kret = krb5_unparse_name(kcontext, princ, &defname);
    CHECK_KRET_L(kret, EIO, done);

    printf("\nTicket cache: %s:%s\nDefault principal: %s\n\n",
           krb5_cc_get_type(kcontext, cache),
           krb5_cc_get_name(kcontext, cache), defname);

    kret = krb5_cc_start_seq_get(kcontext, cache, &cur);
    CHECK_KRET_L(kret, EIO, done);

    while (!(kret = krb5_cc_next_cred(kcontext, cache, &cur, &creds))) {
        printf("Ticket #%d:\n", i);
        print_creds(kcontext, &creds, defname);
        krb5_free_cred_contents(kcontext, &creds);
    }

    kret = krb5_cc_end_seq_get(kcontext, cache, &cur);
    CHECK_KRET_L(kret, EIO, done);

    ret = EOK;
done:
    krb5_cc_close(kcontext, cache);
    krb5_free_unparsed_name(kcontext, defname);
    krb5_free_principal(kcontext, princ);
    krb5_free_context(kcontext);
    return ret;
}

int
main(int argc, const char *argv[])
{
    int opt;
    errno_t ret;
    struct krb5_child_test_ctx *ctx = NULL;
    struct tevent_req *req;

    int pc_debug = 0;
    int pc_timeout = 0;
    const char *pc_user = NULL;
    const char *pc_passwd = NULL;
    const char *pc_realm = NULL;
    const char *pc_ccname = NULL;
    const char *pc_ccname_tp = NULL;
    char *password = NULL;
    bool rm_ccache = true;

    poptContext pc;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug, 0,
          "The debug level to run with", NULL },
        { "user", 'u', POPT_ARG_STRING, &pc_user, 0,
          "The user to log in as", NULL },
        { "password", 'w', POPT_ARG_STRING, &pc_passwd, 0,
          "The authtok to use", NULL },
        { "ask-password", 'W', POPT_ARG_NONE, NULL, 'W',
          "Ask interactively for authtok", NULL },
        { "ccname", 'c', POPT_ARG_STRING, &pc_ccname, 0,
           "Force usage of a certain credential cache", NULL },
        { "ccname-template", 't', POPT_ARG_STRING, &pc_ccname_tp, 0,
           "Specify the credential cache template", NULL },
        { "realm", 'r', POPT_ARG_STRING, &pc_realm, 0,
          "The Kerberos realm to use", NULL },
        { "keep-ccache", 'k', POPT_ARG_NONE, NULL, 'k',
          "Do not delete the ccache when the tool finishes", NULL },
        { "timeout", '\0', POPT_ARG_INT, &pc_timeout, 0,
          "The timeout for the child, in seconds", NULL },
        POPT_TABLEEND
    };

    debug_prg_name = argv[0];
    pc = poptGetContext(NULL, argc, argv, long_options, 0);

    while ((opt = poptGetNextOpt(pc)) > 0) {
        switch(opt) {
        case 'W':
            errno = 0;
            password = getpass("Enter password:");
            if (!password) {
                return 1;
            }
            break;
        case 'k':
            rm_ccache = false;
            break;
        default:
            DEBUG(SSSDBG_FATAL_FAILURE, "Unexpected option\n");
            return 1;
        }
    }

    DEBUG_CLI_INIT(pc_debug);

    if (opt != -1) {
        poptPrintUsage(pc, stderr, 0);
        fprintf(stderr, "%s", poptStrerror(opt));
        return 1;
    }

    if (!pc_user) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Please specify the user\n");
        poptPrintUsage(pc, stderr, 0);
        return 1;
    }

    if (!pc_realm) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Please specify the realm\n");
        poptPrintUsage(pc, stderr, 0);
        return 1;
    }

    if (!password && !pc_passwd) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Password was not provided or asked for\n");
        poptPrintUsage(pc, stderr, 0);
        return 1;
    }

    if (pc_ccname && pc_ccname_tp) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Both ccname and ccname template specified, "
               "will prefer ccname\n");
    }

    ret = setup_krb5_child_test(NULL, &ctx);
    if (ret != EOK) {
        poptPrintUsage(pc, stderr, 0);
        fprintf(stderr, "%s", poptStrerror(opt));
        return 3;
    }

    ctx->kr = create_dummy_req(ctx, pc_user, password ? password : pc_passwd,
                               pc_realm, pc_ccname, pc_ccname_tp, pc_timeout);
    if (!ctx->kr) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Cannot create Kerberos request\n");
        ret = 4;
        goto done;
    }

    req = handle_child_send(ctx, ctx->ev, ctx->kr);
    if (!req) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Cannot create child request\n");
        ret = 4;
        goto done;
    }
    tevent_req_set_callback(req, child_done, ctx);

    while (ctx->done == false) {
         tevent_loop_once(ctx->ev);
    }

    printf("Child returned %d\n", ctx->child_ret);

    ret = parse_krb5_child_response(ctx, ctx->buf, ctx->len,
                                    ctx->kr->pd, 0, &ctx->res);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not parse child response\n");
        ret = 5;
        goto done;
    }

    if (!ctx->res->ccname) {
        fprintf(stderr, "No ccname returned\n");
        ret = 6;
        goto done;
    }

    print_ccache(ctx->res->ccname);

    ret = 0;
done:
    if (rm_ccache && ctx->res
            && ctx->res->ccname
            && ctx->kr) {
        sss_krb5_cc_destroy(ctx->res->ccname, ctx->kr->uid, ctx->kr->gid);
    }
    free(password);
    talloc_free(ctx);
    poptFreeContext(pc);
    return ret;
}
