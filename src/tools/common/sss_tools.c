/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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

#include <talloc.h>
#include <stdlib.h>
#include <string.h>
#include <popt.h>

#include "config.h"
#include "util/util.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"
#include "tools/common/sss_tools.h"

static void sss_tool_print_common_opts(int min_len)
{
    ERROR("Help options:\n");
    fprintf(stderr, "  %-*s\t %s\n", min_len, "-?, --help",
                    _("Show this for a command"));
    fprintf(stderr, "  %-*s\t %s\n", min_len, "--usage",
                    _("Show brief usage message for a command"));
    ERROR("\n");

    ERROR("Debug options:\n");
    fprintf(stderr, "  %-*s\t %s\n", min_len, "--debug",
                    _("Enable debug log level of sssctl tool"));
}

static struct poptOption *sss_tool_common_opts_table(void)
{
    static struct poptOption common_opts[] = {
        {"debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, NULL,
            0, NULL, NULL },
        POPT_TABLEEND
    };

    common_opts[0].descrip = _("The debug level to run with");

    return common_opts;
}

static void sss_tool_common_opts(struct sss_tool_ctx *tool_ctx,
                                 int *argc, const char **argv)
{
    poptContext pc;
    int debug = SSSDBG_TOOLS_DEFAULT;
    int orig_argc = *argc;
    int help = 0;

    struct poptOption options[] = {
        {"debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_STRIP, &debug,
            0, _("The debug level to run with"), NULL },
        {"help", '?', POPT_ARG_VAL | POPT_ARGFLAG_DOC_HIDDEN, &help,
            1, NULL, NULL },
        POPT_TABLEEND
    };

    pc = poptGetContext(argv[0], orig_argc, argv, options, 0);
    while (poptGetNextOpt(pc) != -1) {
        /* do nothing */
    }

    /* Strip common options from arguments. We will discard_const here,
     * since it is not worth the trouble to convert it back and forth. */
    *argc = poptStrippedArgv(pc, orig_argc, discard_const_p(char *, argv));
    tool_ctx->print_help = help;

    DEBUG_CLI_INIT(debug);

    poptFreeContext(pc);
}

static errno_t sss_tool_confdb_init(TALLOC_CTX *mem_ctx,
                                    struct confdb_ctx **_confdb)
{
    struct confdb_ctx *confdb;
    char *path;
    errno_t ret;
    struct stat statbuf;

    path = talloc_asprintf(mem_ctx, "%s/%s", DB_PATH, CONFDB_FILE);
    if (path == NULL) {
        return ENOMEM;
    }

    ret = stat(path, &statbuf);
    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Can't access '%s', probably SSSD isn't configured\n", path);
        return ret;
    }

    ret = confdb_init(mem_ctx, &confdb, path);
    talloc_zfree(path);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to connect to config DB [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    if (_confdb != NULL) {
        *_confdb = confdb;
    }

    return EOK;
}

static errno_t sss_tool_domains_init(TALLOC_CTX *mem_ctx,
                                     struct confdb_ctx *confdb,
                                     struct sss_domain_info **_domains)
{
    struct sss_domain_info *domains;
    struct sss_domain_info *dom;
    errno_t ret;

    ret = confdb_get_domains(confdb, &domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup domains [%d]: %s\n",
                                   ret, sss_strerror(ret));
        return ret;
    }

    ret = sysdb_init(mem_ctx, domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not initialize connection to the sysdb\n");
        return ret;
    }

    for (dom = domains; dom != NULL;
            dom = get_next_domain(dom, SSS_GND_DESCEND)) {
        if (!IS_SUBDOMAIN(dom)) {
            /* Get flat name and domain ID (SID) from the cache
             * if available */
            ret = sysdb_master_domain_update(dom);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE, "Failed to update domain %s.\n",
                                            dom->name);
            }

            /* Update list of subdomains for this domain */
            ret = sysdb_update_subdomains(dom, confdb);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Failed to update subdomains for domain %s.\n",
                      dom->name);
            }
        }
    }

    for (dom = domains; dom != NULL;
            dom = get_next_domain(dom, SSS_GND_DESCEND)) {
        ret = sss_names_init(mem_ctx, confdb, dom->name, &dom->names);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sss_names_init() failed\n");
            return ret;
        }
    }

    *_domains = domains;

    return ret;
}

static errno_t sss_tool_init(TALLOC_CTX *mem_ctx,
                             int *argc, const char **argv,
                             struct sss_tool_ctx **_tool_ctx)
{
    struct sss_tool_ctx *tool_ctx;

    tool_ctx = talloc_zero(mem_ctx, struct sss_tool_ctx);
    if (tool_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed\n");
        return ENOMEM;
    }

    sss_tool_common_opts(tool_ctx, argc, argv);
    *_tool_ctx = tool_ctx;

    return EOK;
}

static bool sss_tool_is_delimiter(struct sss_route_cmd *command)
{
    if (command->command != NULL && command->command[0] == '\0') {
        return true;
    }

    return false;
}

static bool sss_tools_handles_init_error(struct sss_route_cmd *command,
                                         errno_t init_err)
{
    if (init_err == EOK) {
        return true;
    }

    return command->handles_init_err == init_err;
}

static size_t sss_tool_max_length(struct sss_route_cmd *commands)
{
    size_t max = 0;
    size_t len;
    int i;

    for (i = 0; commands[i].command != NULL; i++) {
        if (sss_tool_is_delimiter(&commands[i])) {
            continue;
        }

        len = strlen(commands[i].command);
        if (max < len) {
            max = len;
        }
    }

    return max;
}

static void sss_tool_usage(const char *tool_name, struct sss_route_cmd *commands)
{
    int min_len;
    int i;

    ERROR("Usage:\n%s COMMAND COMMAND-ARGS\n\n", tool_name);
    ERROR("Available commands:\n");

    min_len = sss_tool_max_length(commands);

    for (i = 0; commands[i].command != NULL; i++) {
        if (sss_tool_is_delimiter(&commands[i])) {
            fprintf(stderr, "\n%s\n", commands[i].description);
            continue;
        }

        if (commands[i].description == NULL) {
            fprintf(stderr, "* %40s\n", commands[i].command);
        } else {
            fprintf(stderr, "* %-*s\t %s\n",
                    min_len, commands[i].command, commands[i].description);
        }
    }

    ERROR("\n");
    sss_tool_print_common_opts(min_len);
}

static int tool_cmd_init(struct sss_tool_ctx *tool_ctx,
                         struct sss_route_cmd *command)
{
    int ret;
    uid_t uid;

    if (!(command->flags & SSS_TOOL_FLAG_SKIP_ROOT_CHECK)) {
        uid = getuid();
        if (uid != 0) {
            ERROR("'%s' must be run as root\n", command->command);
            return EXIT_FAILURE;
        }
    }

    if (command->flags & SSS_TOOL_FLAG_SKIP_CMD_INIT) {
        return EOK;
    }

    /* Connect to confdb. */
    ret = sss_tool_confdb_init(tool_ctx, &tool_ctx->confdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to open confdb [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* Setup domains. */
    ret = sss_tool_domains_init(tool_ctx, tool_ctx->confdb, &tool_ctx->domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup domains [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = confdb_get_string(tool_ctx->confdb, tool_ctx,
                            CONFDB_MONITOR_CONF_ENTRY,
                            CONFDB_MONITOR_DEFAULT_DOMAIN,
                            NULL, &tool_ctx->default_domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get the default domain [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    return ret;
}

static errno_t sss_tool_route(int argc, const char **argv,
                              struct sss_tool_ctx *tool_ctx,
                              struct sss_route_cmd *commands,
                              void *pvt)
{
    struct sss_cmdline cmdline;
    const char *cmd;
    int i;
    int ret;

    if (commands == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: commands can't be NULL!\n");
        return EINVAL;
    }

    if (argc < 2) {
        sss_tool_usage(argv[0], commands);
        return EINVAL;
    }

    cmd = argv[1];
    for (i = 0; commands[i].command != NULL; i++) {
        if (sss_tool_is_delimiter(&commands[i])) {
            continue;
        }

        if (strcmp(commands[i].command, cmd) == 0) {
            cmdline.exec = argv[0];
            cmdline.command = argv[1];
            cmdline.argc = argc - 2;
            cmdline.argv = argv + 2;

            if (!tool_ctx->print_help) {
                ret = tool_cmd_init(tool_ctx, &commands[i]);

                if (!sss_tools_handles_init_error(&commands[i], ret)) {
                    DEBUG(SSSDBG_FATAL_FAILURE,
                          "Command %s does not handle initialization error [%d] %s\n",
                          cmdline.command, ret, sss_strerror(ret));
                    return ret;
                }
            }

            return commands[i].fn(&cmdline, tool_ctx, pvt);
        }
    }

    sss_tool_usage(argv[0], commands);
    return EINVAL;
}

static struct poptOption *nonnull_popt_table(struct poptOption *options)
{
    static struct poptOption empty[] = {
        POPT_TABLEEND
    };

    if (options == NULL) {
        return empty;
    }

    return options;
}

errno_t sss_tool_popt_ex(struct sss_cmdline *cmdline,
                         struct poptOption *options,
                         const char *extended_help,
                         enum sss_tool_opt require_option,
                         sss_popt_fn popt_fn,
                         void *popt_fn_pvt,
                         const char *fopt_name,
                         const char *fopt_help,
                         enum sss_tool_opt fopt_require,
                         const char **_fopt,
                         bool *_opt_set)
{
    struct poptOption opts_table[] = {
        {NULL, '\0', POPT_ARG_INCLUDE_TABLE, nonnull_popt_table(options), \
         0, _("Command options:"), NULL },
        {NULL, '\0', POPT_ARG_INCLUDE_TABLE, sss_tool_common_opts_table(), \
         0, NULL, NULL },
        POPT_AUTOHELP
        POPT_TABLEEND
    };
    const char *fopt;
    char *help;
    poptContext pc;
    bool opt_set;
    int ret;

    /* Set output parameter _fopt to NULL value if present. */
    if (_fopt != NULL) {
        *_fopt = NULL;
    }

    /* Create help option string. We always need to append command name since
     * we use POPT_CONTEXT_KEEP_FIRST. */
    if (fopt_name == NULL) {
        help = talloc_asprintf(NULL, "%s %s %s", cmdline->exec,
                               cmdline->command, _("[OPTIONS...]"));
    } else {
        help = talloc_asprintf(NULL, "%s %s %s %s", cmdline->exec,
                               cmdline->command, fopt_name, _("[OPTIONS...]"));
    }
    if (help == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed\n");
        return ENOMEM;
    }

    if (extended_help != NULL) {
        help = talloc_asprintf_append(help, "\n\n%s", extended_help);
        if (help == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf_append() failed\n");
            return ENOMEM;
        }
    }

    /* Create popt context. This function is supposed to be called on
     * command argv which does not contain executable (argv[0]), therefore
     * we need to use KEEP_FIRST that ensures argv[0] is also processed. */
    pc = poptGetContext(cmdline->exec, cmdline->argc, cmdline->argv,
                        opts_table, POPT_CONTEXT_KEEP_FIRST);

    poptSetOtherOptionHelp(pc, help);

    /* Parse options. Invoke custom function if provided. If no parsing
     * function is provided, print error on unknown option. */
    while ((ret = poptGetNextOpt(pc)) != -1) {
        if (popt_fn != NULL) {
            ret = popt_fn(pc, ret, popt_fn_pvt);
            if (ret != EOK) {
                goto done;
            }
        } else {
            ERROR("Invalid option %s: %s\n\n",
                  poptBadOption(pc, 0), poptStrerror(ret));
            poptPrintHelp(pc, stderr, 0);
            ret = EINVAL;
            goto done;
        }
    }

    /* Parse free option which is required if requested and fopt_require
     * is SSS_TOOL_OPT_REQUIRED */
    opt_set = true;
    fopt = poptGetArg(pc);
    if (_fopt != NULL) {
        if (fopt == NULL) {
            if (fopt_require == SSS_TOOL_OPT_REQUIRED) {
                ERROR("Missing option: %s\n\n", fopt_help);
                poptPrintHelp(pc, stderr, 0);
                ret = EINVAL;
                goto done;
            }
            opt_set = false;
        }

        /* No more arguments expected. If something follows it is an error. */
        if (poptGetArg(pc)) {
            ERROR("Only one free argument is expected!\n\n");
            poptPrintHelp(pc, stderr, 0);
            ret = EINVAL;
            goto done;
        }

        if (fopt != NULL) {
            *_fopt = strdup(fopt);
            if (*_fopt == NULL) {
                ERROR("Out of memory!");
                ret = ENOMEM;
                goto done;
            }
        }
    } else if (_fopt == NULL && fopt != NULL) {
        /* Unexpected free argument. */
        ERROR("Unexpected parameter: %s\n\n", fopt);
        poptPrintHelp(pc, stderr, 0);
        ret = EINVAL;
        goto done;
    }

    if ((_fopt != NULL && fopt_require == SSS_TOOL_OPT_REQUIRED && cmdline->argc < 2)
            || cmdline->argc < 1) {
        opt_set = false;

        /* If at least one option is required and not provided, print error. */
        if (require_option == SSS_TOOL_OPT_REQUIRED) {
            ERROR("At least one option is required!\n\n");
            poptPrintHelp(pc, stderr, 0);
            ret = EINVAL;
            goto done;
        }
    }

    if (_opt_set != NULL) {
        *_opt_set = opt_set;
    }

    ret = EOK;

done:
    poptFreeContext(pc);
    talloc_free(help);
    if (ret != EOK && _fopt != NULL) {
        free(discard_const(*_fopt));
        *_fopt = NULL;
    }

    return ret;
}

errno_t sss_tool_popt(struct sss_cmdline *cmdline,
                      struct poptOption *options,
                      enum sss_tool_opt require_option,
                      sss_popt_fn popt_fn,
                      void *popt_fn_pvt)
{
    return sss_tool_popt_ex(cmdline, options, NULL, require_option,
                            popt_fn, popt_fn_pvt, NULL, NULL,
                            SSS_TOOL_OPT_REQUIRED, NULL, NULL);
}

int sss_tool_main(int argc, const char **argv,
                  struct sss_route_cmd *commands,
                  void *pvt)
{
    struct sss_tool_ctx *tool_ctx;
    errno_t ret;

    ret = sss_tool_init(NULL, &argc, argv, &tool_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tool context\n");
        return EXIT_FAILURE;
    }

    ret = sss_tool_route(argc, argv, tool_ctx, commands, pvt);
    SYSDB_VERSION_ERROR(ret);
    talloc_free(tool_ctx);
    if (ret != EOK) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

errno_t sss_tool_parse_name(TALLOC_CTX *mem_ctx,
                            struct sss_tool_ctx *tool_ctx,
                            const char *input,
                            const char **_username,
                            struct sss_domain_info **_domain)
{
    char *username = NULL;
    char *domname = NULL;
    struct sss_domain_info *domain;
    int ret;

    ret = sss_parse_name_for_domains(mem_ctx, tool_ctx->domains,
                                     tool_ctx->default_domain, input,
                                     &domname, &username);
    if (ret == EAGAIN) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to find domain. The domain name may "
              "be a subdomain that was not yet found.\n");
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse name [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    domain = find_domain_by_name(tool_ctx->domains, domname, true);

    *_username = username;
    *_domain = domain;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_zfree(username);
        talloc_zfree(domname);
    }

    return ret;
}

errno_t sss_tool_connect_to_confdb(TALLOC_CTX *ctx, struct confdb_ctx **cdb_ctx)
{
    int ret;
    char *confdb_path = NULL;

    confdb_path = talloc_asprintf(ctx, "%s/%s", DB_PATH, CONFDB_FILE);
    if (confdb_path == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not allocate memory for confdb path\n");
        return ENOMEM;
    }

    ret = confdb_init(ctx, cdb_ctx, confdb_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not initialize connection to the confdb\n");
    }

    talloc_free(confdb_path);
    return ret;
}
