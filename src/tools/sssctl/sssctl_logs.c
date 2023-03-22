/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#include <stdlib.h>
#include <limits.h>
#include <talloc.h>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>
#include <utime.h>
#include <ldb.h>
#include <popt.h>
#include <stdio.h>
#include <glob.h>

#include "util/util.h"
#include "tools/common/sss_tools.h"
#include "tools/common/sss_process.h"
#include "tools/sssctl/sssctl.h"
#include "tools/tools_util.h"
#include "confdb/confdb.h"
#include "sss_iface/sss_iface_sync.h"
#include "responder/ifp/ifp_iface/ifp_iface_sync.h"

#define LOG_FILE(file) " " LOG_PATH "/" file
#define LOG_FILES LOG_FILE("*.log")
#define SSS_ANALYZE SSSD_LIBEXEC_PATH"/sss_analyze"

#define CHECK(expr, done, msg) do { \
    if (expr) { \
        ERROR(msg "\n"); \
        goto done; \
    } \
} while(0)

#define POPT_SERV_OPTION(NAME, VAR, DESC) \
            {services[SERV_ ## NAME].name, '\0', POPT_BIT_SET, &VAR, \
             services[SERV_ ## NAME].mask, DESC, NULL}

#define STARTS_WITH(s, p)     (strncmp((s), (p), strlen(p)) == 0)
#define REMOVE_PREFIX(s, p)   (STARTS_WITH(s, p) ? (s) + strlen(p) : (s))
#define IS_DOMAIN(c)          STARTS_WITH((c), "domain/")
#define DOMAIN_NAME(c)        REMOVE_PREFIX((c), "domain/")
#define EMPTY_TARGETS(t)      ((t)[0] == NULL)

enum debug_level_action {
    ACTION_SET,
    ACTION_GET
};

struct debuglevel_tool_ctx {
    struct confdb_ctx *confdb;
    char **sections;
};

struct sssctl_logs_opts {
    int delete;
    int archived;
};

struct sssctl_service_desc {
    const char *name;
    int mask;
};

enum serv_idx {
    SERV_SSSD,
    SERV_NSS,
    SERV_PAM,
    SERV_SUDO,
    SERV_AUTOFS,
    SERV_SSH,
    SERV_PAC,
    SERV_IFP,
    SERV_COUNT
};

struct sssctl_service_desc services[] = {
    { "sssd",   1U << SERV_SSSD  },
    { "nss",    1U << SERV_NSS   },
    { "pam",    1U << SERV_PAM   },
    { "sudo",   1U << SERV_SUDO  },
    { "autofs", 1U << SERV_AUTOFS},
    { "ssh",    1U << SERV_SSH   },
    { "pac",    1U << SERV_PAC   },
    { "ifp",    1U << SERV_IFP   }
};

static struct sbus_sync_connection *connect_to_sbus(TALLOC_CTX *mem_ctx)
{
    struct sbus_sync_connection *conn;

    conn = sbus_sync_connect_private(mem_ctx, SSS_MONITOR_ADDRESS, NULL);
    if (conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to connect to the sbus monitor\n");
    }

    return conn;
}

static const char *get_busname(TALLOC_CTX *mem_ctx, struct confdb_ctx *confdb,
                               const char *component)
{
    errno_t ret;
    const char *busname;
    struct sss_domain_info *domain;

    if (strcmp(component, "sssd") == 0) {
        busname = talloc_strdup(mem_ctx, SSS_BUS_MONITOR);
    } else if (IS_DOMAIN(component)) {
        ret = confdb_get_domain(confdb, DOMAIN_NAME(component), &domain);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unknown domain: %s\n", component);
            busname = NULL;
            goto done;
        }

        busname = sss_iface_domain_bus(mem_ctx, domain);
    } else {
        busname = talloc_asprintf(mem_ctx, "sssd.%s", component);
    }

done:
    return busname;
}

/* in_out_value is an input argument when action is ACTION_SET; it is an output
 * argument when action is ACTION_GET. */
static errno_t do_debug_level(enum debug_level_action action,
                                  struct sbus_sync_connection *conn,
                                  struct confdb_ctx *confdb,
                                  const char *component,
                                  uint32_t *in_out_value)
{
    errno_t ret;
    uint32_t value;
    const char *busname;
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);

    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    busname = get_busname(tmp_ctx, confdb, component);
    if (busname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to create the bus name for %s\n",
              component);
    }

    if (action == ACTION_GET) {
        ret = sbus_get_service_debug_level(conn, busname, SSS_BUS_PATH, &value);
        if (ret != EOK) {
            ret = ENOENT;
            goto done;
        }

        *in_out_value = value;
    } else {
        ret = sbus_set_service_debug_level(conn, busname, SSS_BUS_PATH,
                                           *in_out_value);
        if (ret != EOK) {
            ret = ENOENT;
            goto done;
        }
    }
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t sssctl_do_debug_level(enum debug_level_action action,
                                         struct debuglevel_tool_ctx *tool_ctx,
                                         const char **targets,
                                         uint32_t debug_to_set)
{
    bool all_targets = EMPTY_TARGETS(targets);
    errno_t ret = EOK;
    errno_t final_ret = EOK;
    uint32_t current_level = SSSDBG_INVALID;
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);
    const char *stripped_target;
    const char **curr_target;
    struct sbus_sync_connection *conn;

    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    conn = connect_to_sbus(tmp_ctx);
    if (conn == NULL) {
        ERROR("SSSD is not running.\n");
        ret = EIO;
        goto fini;
    }

    curr_target = (all_targets ?
                   discard_const_p(const char *, tool_ctx->sections) : targets);
    while (*curr_target != NULL) {
        stripped_target = REMOVE_PREFIX(*curr_target, "config/");

        if (action == ACTION_GET) {
            ret = do_debug_level(ACTION_GET, conn, tool_ctx->confdb,
                                 stripped_target, &current_level);
            CHECK(ret != EOK && ret != ENOENT, fini,
                  "Could not read the debug level.");

            if (ret == EOK) {
                PRINT(_("%1$-25s %2$#.4x\n"), stripped_target, current_level);
            } else {
               if (!all_targets) {
                    if (IS_DOMAIN(stripped_target)) {
                        PRINT(_("%1$-25s Unknown domain\n"), stripped_target);
                    } else {
                        PRINT(_("%1$-25s Unreachable service\n"), stripped_target);
                    }
                    final_ret = ENOENT;
                }
            }
        } else {
            ret = do_debug_level(ACTION_SET, conn, tool_ctx->confdb,
                                 stripped_target, &debug_to_set);
            CHECK(ret != EOK && ret != ENOENT, fini,
                  "Could not set the debug level.");
            if (ret == ENOENT && !all_targets) {
                final_ret = ret;
            }
        }
        curr_target++;
    }

    if (ret == EOK) {
        ret = final_ret;
    }

fini:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t get_confdb_sections(TALLOC_CTX *ctx, struct confdb_ctx *confdb,
                            char ***output_sections)
{
    int ret;
    int domain_count = 0;
    int i = 0;
    struct sss_domain_info *domain = NULL;
    struct sss_domain_info *domain_list = NULL;
    char **sections;
    const char *known_services[] = {
        CONFDB_MONITOR_CONF_ENTRY,
        CONFDB_NSS_CONF_ENTRY,
        CONFDB_PAM_CONF_ENTRY,
        CONFDB_PAC_CONF_ENTRY,
        CONFDB_SSH_CONF_ENTRY,
        CONFDB_SUDO_CONF_ENTRY,
        CONFDB_AUTOFS_CONF_ENTRY,
        CONFDB_IFP_CONF_ENTRY,
    };
    static const int known_services_count = sizeof(known_services)
                                            / sizeof(*known_services);
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);

    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    /* get domains */
    ret = confdb_get_domains(confdb, &domain_list);
    if (ret != EOK)
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get domain list\n");

    for (domain = domain_list;
         domain;
         domain = get_next_domain(domain, 0)) {
        domain_count++;
    }

    /* allocate output space */
    sections = talloc_array(ctx, char *,
                            domain_count + known_services_count + 1);
    if (sections == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not allocate memory for sections\n");
        ret = ENOMEM;
        goto fail;
    }

    for (i = 0; i < known_services_count; i++) {
        sections[i] = talloc_strdup(tmp_ctx, known_services[i]);
        if (sections[i] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup() failed\n");
            ret = ENOMEM;
            goto fail;
        }
    }

    for (domain = domain_list;
         domain;
         domain = get_next_domain(domain, 0), i++) {
        sections[i] = talloc_asprintf(tmp_ctx, CONFDB_DOMAIN_PATH_TMPL,
                                      domain->name);
        if (sections[i] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf() failed\n");
            ret = ENOMEM;
            goto fail;
        }
    }

    /* add NULL to the end */
    sections[i] = NULL;

    *output_sections = talloc_steal(ctx, sections);

    return EOK;
fail:
    talloc_free(tmp_ctx);
    return ret;
}

static const char **get_targets(TALLOC_CTX *mem_ctx, int services_mask,
                                const char **domainv)
{
    int i;
    int count = 1;
    const char **targets = NULL;
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);

    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return NULL;
    }

    targets = talloc_zero_array(tmp_ctx, const char *, count);
    if (targets == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not allocate memory for the list of targets\n");
        goto done;
    }

    if (services_mask != 0) {
        for (i = 0; i < SERV_COUNT; i++) {
            if (services_mask == 0 || (services_mask & services[i].mask) != 0) {
                targets = talloc_realloc(tmp_ctx, targets, const char *, count + 1);
                if (targets == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Could not allocate memory for the list of targets\n");
                    goto done;
                }
                targets[count - 1] = talloc_strdup(tmp_ctx, services[i].name);
                targets[count++] = NULL;
            }
        }
    }

    if (domainv != NULL) {
        for (; *domainv != NULL; domainv++) {
            targets = talloc_realloc(tmp_ctx, targets, const char *, count + 1);
            if (targets == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Could not allocate memory for the list of targets\n");
                goto done;
            }
            if (IS_DOMAIN(*domainv)) {
                targets[count - 1] = talloc_strdup(tmp_ctx, *domainv);
            } else {
                targets[count - 1] = talloc_asprintf(tmp_ctx, "domain/%s", *domainv);
            }
            targets[count++] = NULL;
        }
    }

    targets = talloc_steal(mem_ctx, targets);
    for (i = 0; i < count; i++) {
        targets[i] = talloc_steal(mem_ctx, targets[i]);
    }

done:
    talloc_free(tmp_ctx);
    return targets;
}

int parse_debug_level(const char *strlevel)
{
    long value;
    char *endptr;

    errno = 0;
    value = strtol(strlevel, &endptr, 0);
    if ((errno != 0) || (endptr == strlevel) || (*endptr != '\0')) {
        return SSSDBG_INVALID;
    }

    return debug_convert_old_level(value);
}

errno_t sssctl_logs_remove(struct sss_cmdline *cmdline,
                           struct sss_tool_ctx *tool_ctx,
                           void *pvt)
{
    struct sssctl_logs_opts opts = {0};
    errno_t ret;
    glob_t globbuf;

    /* Parse command line. */
    struct poptOption options[] = {
        {"delete", 'd', POPT_ARG_NONE, &opts.delete, 0, _("Delete log files instead of truncating"), NULL },
        POPT_TABLEEND
    };

    ret = sss_tool_popt(cmdline, options, SSS_TOOL_OPT_OPTIONAL, NULL, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    if (opts.delete) {
        PRINT("Deleting log files...\n");
        ret = sss_remove_subtree(LOG_PATH);
        if (ret != EOK) {
            ERROR("Unable to remove log files\n");
            return ret;
        }

        sss_signal(SIGHUP);
    } else {
        globbuf.gl_offs = 4;
        ret = glob(LOG_PATH"/*.log", GLOB_ERR|GLOB_DOOFFS, NULL, &globbuf);
        if (ret != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to expand log files list\n");
            return ret;
        }
        globbuf.gl_pathv[0] = discard_const_p(char, "truncate");
        globbuf.gl_pathv[1] = discard_const_p(char, "--no-create");
        globbuf.gl_pathv[2] = discard_const_p(char, "--size");
        globbuf.gl_pathv[3] = discard_const_p(char, "0");

        PRINT("Truncating log files...\n");
        ret = sssctl_run_command((const char * const*)globbuf.gl_pathv);
        globfree(&globbuf);
        if (ret != EOK) {
            ERROR("Unable to truncate log files\n");
            return ret;
        }
    }

    return EOK;
}

errno_t sssctl_logs_fetch(struct sss_cmdline *cmdline,
                          struct sss_tool_ctx *tool_ctx,
                          void *pvt)
{
    const char *file = NULL;
    errno_t ret;
    glob_t globbuf;

    /* Parse command line. */
    ret = sss_tool_popt_ex(cmdline, NULL, SSS_TOOL_OPT_OPTIONAL, NULL, NULL,
                           "FILE", "Output file", SSS_TOOL_OPT_REQUIRED,
                           &file, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        goto done;
    }

    globbuf.gl_offs = 3;
    ret = glob(LOG_PATH"/*.log", GLOB_ERR|GLOB_DOOFFS, NULL, &globbuf);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to expand log files list\n");
        goto done;
    }
    globbuf.gl_pathv[0] = discard_const_p(char, "tar");
    globbuf.gl_pathv[1] = discard_const_p(char, "-czf");
    globbuf.gl_pathv[2] = discard_const_p(char, file);

    PRINT("Archiving log files into %s...\n", file);
    ret = sssctl_run_command((const char * const*)globbuf.gl_pathv);
    globfree(&globbuf);
    if (ret != EOK) {
        ERROR("Unable to archive log files\n");
        goto done;
    }

done:
    free(discard_const(file));

    return ret;
}

errno_t sssctl_debug_level(struct sss_cmdline *cmdline,
                           struct sss_tool_ctx *tool_ctx,
                           void *pvt)
{
    int ret;
    int pc_services = 0;
    uint32_t debug_to_set = SSSDBG_INVALID;
    const char **pc_domains = NULL;
    const char **targets = NULL;
    const char *debug_as_string = NULL;

    struct debuglevel_tool_ctx *ctx = NULL;
    struct poptOption long_options[] = {
        {"domain", '\0', POPT_ARG_ARGV, &pc_domains,
            0, _("Target a specific domain"), _("domain")},
        POPT_SERV_OPTION(SSSD, pc_services, _("Target the SSSD service")),
        POPT_SERV_OPTION(NSS, pc_services, _("Target the NSS service")),
        POPT_SERV_OPTION(PAM, pc_services, _("Target the PAM service")),
        POPT_SERV_OPTION(SUDO, pc_services, _("Target the SUDO service")),
        POPT_SERV_OPTION(AUTOFS, pc_services, _("Target the AUTOFS service")),
        POPT_SERV_OPTION(SSH, pc_services, _("Target the SSH service")),
        POPT_SERV_OPTION(PAC, pc_services, _("Target the PAC service")),
        POPT_SERV_OPTION(IFP, pc_services, _("Target the IFP service")),
        POPT_TABLEEND
    };

    /* allocate context */
    ctx = talloc_zero(NULL, struct debuglevel_tool_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not allocate memory for tools context\n");
        ret = ENOMEM;
        goto fini;
    }

    ret = sss_tool_popt_ex(cmdline, long_options, SSS_TOOL_OPT_OPTIONAL, NULL,
                           NULL, "DEBUG_LEVEL_TO_SET",
                           _("Specify debug level you want to set"),
                           SSS_TOOL_OPT_OPTIONAL, &debug_as_string, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        goto fini;
    }

    CHECK_ROOT(ret, debug_prg_name);

    if (debug_as_string != NULL) {
        debug_to_set = (uint32_t) parse_debug_level(debug_as_string);
        CHECK(debug_to_set == SSSDBG_INVALID, fini, "Invalid debug level.");
    }

    /* Create a list with all the target names (services + domains) */
    targets = get_targets(ctx, pc_services, pc_domains);
    CHECK(targets == NULL, fini, "Could not allocate memory.");

    ret = sss_tool_connect_to_confdb(ctx, &ctx->confdb);
    CHECK(ret != EOK, fini, "Could not connect to configuration database.");

    ret = get_confdb_sections(ctx, ctx->confdb, &ctx->sections);
    CHECK(ret != EOK, fini, "Could not get all configuration sections.");

    if (debug_as_string == NULL) {
        ret = sssctl_do_debug_level(ACTION_GET, ctx, targets, 0);
    } else {
        ret = sssctl_do_debug_level(ACTION_SET, ctx, targets, debug_to_set);
    }

    /* Only report missing components that the user requested,
       except for the monitor (sssd not running) */
    if (ret != ENOENT && ret != EIO && EMPTY_TARGETS(targets)) {
        ret = EOK;
    }

fini:
    talloc_free(ctx);
    free(discard_const(debug_as_string));

    return ret;
}

errno_t sssctl_analyze(struct sss_cmdline *cmdline,
                       struct sss_tool_ctx *tool_ctx,
                       void *pvt)
{
#ifndef BUILD_CHAIN_ID
    PRINT("ERROR: Tevent chain ID support missing, log analyzer is unsupported.\n");
    return EOK;
#endif
    errno_t ret;

    ret = sssctl_wrap_command(SSS_ANALYZE, NULL, cmdline, tool_ctx, pvt);

    return ret;
}
