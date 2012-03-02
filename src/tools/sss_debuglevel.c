/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2011 Red Hat

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
#include <limits.h>
#include <talloc.h>
#include <popt.h>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>
#include <utime.h>

#include "config.h"
#include "ldb.h"
#include "util/util.h"
#include "tools/tools_util.h"
#include "confdb/confdb.h"

#define SSSD_PIDFILE            ""PID_PATH"/sssd.pid"
#define MAX_PID_LENGTH          10

#define CHECK(expr, done, msg) do { \
    if (expr) { \
        ERROR(msg "\n"); \
        goto done; \
    } \
} while(0)

struct debuglevel_tool_ctx {
    struct confdb_ctx *confdb;
    char **sections;
};

static errno_t set_debug_level(struct debuglevel_tool_ctx *tool_ctx,
                               int debug_to_set, const char *config_file);
static errno_t send_sighup(void);
static errno_t connect_to_confdb(TALLOC_CTX *ctx, struct confdb_ctx **cdb_ctx);
static errno_t get_confdb_sections(TALLOC_CTX *ctx, struct confdb_ctx *confdb,
                                   char ***output_sections);
static errno_t get_sssd_pid(pid_t *out_pid);
static pid_t parse_pid(const char *strpid);
static int parse_debug_level(const char *strlevel);

int main(int argc, const char **argv)
{
    int ret;
    int pc_debug = SSSDBG_DEFAULT;
    int debug_to_set = SSSDBG_INVALID;
    const char *debug_as_string = NULL;
    const char *config_file = NULL;
    const char *pc_config_file = NULL;
    struct debuglevel_tool_ctx *ctx = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        {"debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug,
            0, _("The debug level to run with"), NULL },
        {"config", 'c', POPT_ARG_STRING, &pc_config_file,
            0, _("Specify a non-default config file"), NULL},
        POPT_TABLEEND
    };
    poptContext pc = NULL;

    debug_prg_name = argv[0];

    /* parse parameters */
    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "DEBUG_LEVEL_TO_SET");
    while((ret = poptGetNextOpt(pc)) != -1) {
        switch(ret) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(ret));
            poptPrintUsage(pc, stderr, 0);
            ret = EXIT_FAILURE;
            goto fini;
        }
    }
    debug_level = debug_convert_old_level(pc_debug);

    /* get debug level */
    debug_as_string = poptGetArg(pc);
    if (debug_as_string == NULL) {
        BAD_POPT_PARAMS(pc, _("Specify debug level you want to set\n"),
                        ret, fini);
    }

    /* get config file */
    if (pc_config_file) {
        config_file = talloc_strdup(ctx, pc_config_file);
    } else {
        config_file = talloc_strdup(ctx, CONFDB_DEFAULT_CONFIG_FILE);
    }

    if (config_file == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup() failed\n"));
        ret = ENOMEM;
        goto fini;
    }

    CHECK_ROOT(ret, debug_prg_name);

    /* free pc_config_file? */
    /* free debug_as_string? */

    debug_to_set = parse_debug_level(debug_as_string);
    CHECK(debug_to_set == SSSDBG_INVALID, fini, "Invalid debug level.");

    /* allocate context */
    ctx = talloc_zero(NULL, struct debuglevel_tool_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not allocate memory for tools context\n"));
        ret = ENOMEM;
        goto fini;
    }

    ret = connect_to_confdb(ctx, &ctx->confdb);
    CHECK(ret != EOK, fini, "Could not connect to configuration database.");

    ret = get_confdb_sections(ctx, ctx->confdb, &ctx->sections);
    CHECK(ret != EOK, fini, "Could not get all configuration sections.");

    ret = set_debug_level(ctx, debug_to_set, config_file);
    CHECK(ret != EOK, fini, "Could not set debug level.");

    ret = send_sighup();
    CHECK(ret != EOK, fini,
          "Could not force sssd processes to reload configuration. "
          "Is sssd running?");

fini:
    poptFreeContext(pc);
    talloc_free(ctx);
    return ret;
}

errno_t set_debug_level(struct debuglevel_tool_ctx *tool_ctx,
                        int debug_to_set, const char *config_file)
{
    int ret;
    int err;
    const char *values[2];
    char **section = NULL;
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);

    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
        return ENOMEM;
    }

    /* convert debug_to_set to string */
    values[0] = talloc_asprintf(tmp_ctx, "0x%.4x", debug_to_set);
    if (values[0] == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not allocate memory for "
              "debug_to_set to string conversion\n"));
        ret = ENOMEM;
        goto done;
    }
    values[1] = NULL;

    /* write to confdb */
    for (section = tool_ctx->sections; *section != NULL; section++) {
        ret = confdb_add_param(tool_ctx->confdb, 1, *section,
                               CONFDB_SERVICE_DEBUG_LEVEL, values);
        if (ret != EOK) {
            goto done;
        }
    }

    /*
     * Change atime and mtime of sssd.conf,
     * so the configuration can be restored on next start.
     */
    errno = 0;
    if (utime(config_file, NULL) == -1 ) {
        err = errno;
        DEBUG(SSSDBG_MINOR_FAILURE, ("Unable to change mtime of \"%s\": %s\n",
              config_file, strerror(err)));
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t send_sighup()
{
    int ret;
    pid_t pid;

    ret = get_sssd_pid(&pid);
    if (ret != EOK) {
        return ret;
    }

    if (kill(pid, SIGHUP) != 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not send SIGHUP to process %d: %s\n",
              pid, strerror(errno)));
        return errno;
    }

    return EOK;
}

errno_t connect_to_confdb(TALLOC_CTX *ctx, struct confdb_ctx **cdb_ctx)
{
    int ret;
    char* confdb_path = NULL;

    confdb_path = talloc_asprintf(ctx, "%s/%s", DB_PATH, CONFDB_FILE);
    if (confdb_path == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not allocate memory for confdb path\n"));
        return ENOMEM;
    }

    ret = confdb_init(ctx, cdb_ctx, confdb_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not initialize connection to the confdb\n"));
    }

    talloc_free(confdb_path);
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
        CONFDB_PAM_CONF_ENTRY
    };
    static const int known_services_count = 3;
    TALLOC_CTX *tmp_ctx = talloc_new(NULL);

    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
        return ENOMEM;
    }

    /* get domains */
    ret = confdb_get_domains(confdb, &domain_list);
    if (ret != EOK)
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to get domain list\n"));

    for (domain = domain_list; domain != NULL; domain = domain->next)
        domain_count++;

    /* allocate output space */
    sections = talloc_array(ctx, char*,
                            domain_count + known_services_count + 1);
    if (sections == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not allocate memory for sections\n"));
        ret = ENOMEM;
        goto fail;
    }

    for (i = 0; i < known_services_count; i++) {
        sections[i] = talloc_strdup(tmp_ctx, known_services[i]);
        if (sections[i] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup() failed\n"));
            ret = ENOMEM;
            goto fail;
        }
    }

    for (domain = domain_list; domain != NULL; domain = domain->next, i++) {
        sections[i] = talloc_asprintf(tmp_ctx, CONFDB_DOMAIN_PATH_TMPL,
                                      domain->name);
        if (sections[i] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_asprintf() failed\n"));
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

errno_t get_sssd_pid(pid_t *out_pid)
{
    int ret;
    FILE *pid_file = NULL;
    char pid_str[MAX_PID_LENGTH] = {'\0'};

    *out_pid = 0;

    errno = 0;
    pid_file = fopen(SSSD_PIDFILE, "r");
    if (pid_file == NULL) {
        ret = errno;
        DEBUG(SSSDBG_MINOR_FAILURE, ("Unable to open pid file \"%s\": %s\n",
              SSSD_PIDFILE, strerror(ret)));
        goto done;
    }

    ret = fread(pid_str, sizeof(char), MAX_PID_LENGTH * sizeof(char), pid_file);
    if (!feof(pid_file)) {
        /* eof not reached */
        ret = ferror(pid_file);
        if (ret != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to read from file \"%s\": %s\n",
                  SSSD_PIDFILE, strerror(ret)));
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, ("File \"%s\" contains invalid pid.\n",
                  SSSD_PIDFILE));
        }
        goto done;
    }

    *out_pid = parse_pid(pid_str);
    if (*out_pid == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("File \"%s\" contains invalid pid.\n", SSSD_PIDFILE));
        ret = EINVAL;
        goto done;
    }

    ret = EOK;

done:
    if (pid_file != NULL) {
        fclose(pid_file);
    }
    return ret;
}

pid_t parse_pid(const char *strpid)
{
    long value;
    char *endptr;

    errno = 0;
    value = strtol(strpid, &endptr, 10);
    if ((errno != 0) || (endptr == strpid)
        || ((*endptr != '\0') && (*endptr != '\n'))) {
        return 0;
    }

    return value;
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
