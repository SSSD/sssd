/*
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <talloc.h>
#include <popt.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"
#include "tools/common/sss_tools.h"
#include "confdb/confdb.h"

#ifndef BUFSIZE
#define BUFSIZE 1024
#endif

#ifndef PASS_MAX
#define PASS_MAX 64
#endif

enum seed_pass_method {
    PASS_PROMPT,
    PASS_FILE
};

struct user_ctx {
    char *domain_name;

    char *name;
    uid_t uid;
    gid_t gid;
    char *gecos;
    char *home;
    char *shell;

    char *password;
};

struct seed_ctx {
    struct confdb_ctx *confdb;
    struct sss_domain_info *domain;
    struct sysdb_ctx *sysdb;

    struct user_ctx *uctx;

    char *password_file;
    enum seed_pass_method password_method;

    bool interact;
    bool user_cached;
};


static int seed_prompt(const char *req)
{
    ssize_t len = 0;
    size_t i = 0;
    char *prompt = NULL;
    int ret = EOK;

    prompt = talloc_asprintf(NULL, _("Enter %s:"), req);
    if (prompt == NULL) {
        ret = ENOMEM;
        goto done;
    }

    while (prompt[i] != '\0') {
       errno = 0;
       len = sss_atomic_write_s(STDOUT_FILENO, &prompt[i++], 1);
       if (len == -1) {
           ret = errno;
           DEBUG(SSSDBG_CRIT_FAILURE, "write failed [%d][%s].\n",
                                       ret, strerror(ret));
           goto done;
       }
    }

done:
    talloc_free(prompt);
    return ret;
}

static int seed_str_input(TALLOC_CTX *mem_ctx,
                          const char *req,
                          char **_input)
{
    char buf[BUFSIZE+1];
    size_t len = 0;
    size_t bytes_read = 0;
    int ret = EOK;

    ret = seed_prompt(req);
    if (ret != EOK) {
        return ret;
    }

    errno = 0;
    while ((bytes_read = sss_atomic_read_s(STDIN_FILENO, buf+len, 1)) != 0) {
        if (bytes_read == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE, "read failed [%d][%s].\n",
                                        ret, strerror(ret));
            return ret;
        }
        if (buf[len] == '\n' || len == BUFSIZE) {
            buf[len] = '\0';
            break;
        }
        len += bytes_read;
    }

    *_input = talloc_strdup(mem_ctx, buf);
    if (*_input == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to allocate input\n");
    }

    return ret;
}

static int seed_id_input(const char *req,
                         uid_t *_id_input)
{
    char buf[BUFSIZE+1];
    size_t len = 0;
    size_t bytes_read = 0;
    char *endptr = NULL;
    int ret = EOK;

    ret = seed_prompt(req);
    if (ret != EOK) {
        return ret;
    }

    errno = 0;
    while ((bytes_read = sss_atomic_read_s(STDIN_FILENO, buf+len, 1)) != 0) {
        if (bytes_read == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE, "read failed [%d][%s].\n",
                                        ret, strerror(ret));
            return ret;
        }
        if (buf[len] == '\n' || len == BUFSIZE) {
            buf[len] = '\0';
            break;
        }
        len += bytes_read;
    }

    if (isdigit(*buf)) {
        errno = 0;
        *_id_input = (uid_t)strtoll(buf, &endptr, 10);
        if (errno != 0) {
            ret = errno;
            DEBUG(SSSDBG_OP_FAILURE, "strtoll failed on [%s]: [%d][%s].\n",
                                      (char *)buf, ret, strerror(ret));
            return ret;
        }
        if (*endptr != '\0') {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "extra characters [%s] after ID [%"SPRIuid"]\n",
                   endptr, *_id_input);
        }
    } else {
        ret = EINVAL;
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get %s input.\n", req);
    }

    return ret;
}

static int seed_password_input_prompt(TALLOC_CTX *mem_ctx, char **_password)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *password = NULL;
    char *temp = NULL;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not allocate temp context\n");
        ret = ENOMEM;
        goto done;
    }

    temp = getpass("Enter temporary password:");
    if (temp == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get prompted password\n");
        ret = EINVAL;
        goto done;
    }

    /* Do not allow empty passwords */
    if (strlen(temp) == 0) {
        ERROR("Empty passwords are not allowed.\n");
        ret = EINVAL;
        goto done;
    }

    password = talloc_strdup(tmp_ctx, temp);
    sss_erase_mem_securely(temp, strlen(temp));
    if (password == NULL) {
        ret = ENOMEM;
        goto done;
    }

    talloc_set_destructor((TALLOC_CTX *)password,
                          sss_erase_talloc_mem_securely);

    temp = getpass("Enter temporary password again:");
    if (temp == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to get prompted password\n");
        ret = EINVAL;
        goto done;
    }

    if (strncmp(temp,password,strlen(password)) != 0) {
        ERROR("Passwords do not match\n");
        DEBUG(SSSDBG_MINOR_FAILURE, "Provided passwords do not match\n");
        ret = EINVAL;
        goto done;
    }

    *_password = talloc_steal(mem_ctx, password);

done:
    talloc_free(tmp_ctx);
    if (temp != NULL) {
        sss_erase_mem_securely(temp, strlen(temp));
    }
    return ret;
}

static int seed_password_input_file(TALLOC_CTX *mem_ctx,
                                    char *filename,
                                    char **_password)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *password = NULL;
    int len = 0;
    uint8_t buf[PASS_MAX+1];
    int fd = -1;
    int ret = EOK;
    int valid_i;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not allocate temp context\n");
        ret = ENOMEM;
        goto done;
    }

    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to open password file "
                                    "[%s] [%d][%s]\n",
                                    filename, errno, strerror(errno));
        ret = EINVAL;
        goto done;
    }

    errno = 0;
    len = sss_atomic_read_s(fd, buf, PASS_MAX + 1);
    if (len == -1) {
        ret = errno;
        DEBUG(SSSDBG_MINOR_FAILURE, "Failed to read password from file "
                                     "[%s] [%d][%s]\n",
                                     filename, ret, strerror(ret));
        close(fd);
        goto done;
    }

    close(fd);

    if (len > PASS_MAX) {
        ERROR("Password file too big.\n");
        ret = EINVAL;
        goto done;
    }

    buf[len] = '\0';

    /* Only the first line is valid (without '\n'). */
    for (valid_i = -1; valid_i + 1 < len; valid_i++) {
        if (buf[valid_i + 1] == '\n') {
            buf[valid_i + 1] = '\0';
            break;
        }
    }

    /* Do not allow empty passwords. */
    if (valid_i < 0) {
        ERROR("Empty passwords are not allowed.\n");
        ret = EINVAL;
        goto done;
    }

    /* valid_i is the last valid index of the password followed by \0.
     * If characters other than \n occur int the rest of the file, it
     * is an error. */
    for (i = valid_i + 2; i < len; i++) {
        if (buf[i] != '\n') {
            ERROR("Multi-line passwords are not allowed.\n");
            ret = EINVAL;
            goto done;
        }
    }

    password = talloc_strdup(tmp_ctx, (char *)buf);
    if (password == NULL) {
        ret = ENOMEM;
        goto done;
    }

    talloc_set_destructor((TALLOC_CTX *)password,
                          sss_erase_talloc_mem_securely);

    *_password = talloc_steal(mem_ctx, password);

done:
    talloc_free(tmp_ctx);
    sss_erase_mem_securely(buf, sizeof(buf));
    return ret;
}

static int seed_interactive_input(TALLOC_CTX *mem_ctx,
                                  struct user_ctx *uctx,
                                  struct user_ctx **_uctx)
{
    struct user_ctx *input_uctx = NULL;
    int ret = EOK;

    input_uctx = talloc_zero(NULL, struct user_ctx);
    if (input_uctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (uctx->name == NULL) {
        ret = seed_str_input(input_uctx, _("username"), &input_uctx->name);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Username interactive input failed.\n");
            goto done;
        }
    } else {
        input_uctx->name = talloc_strdup(input_uctx, uctx->name);
        if (input_uctx->name == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (uctx->uid == 0) {
        ret = seed_id_input(_("UID"), &input_uctx->uid);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "UID interactive input failed.\n");
            goto done;
        }
    } else {
        input_uctx->uid = uctx->uid;
    }

    if (uctx->gid == 0) {
        ret = seed_id_input(_("GID"), &input_uctx->gid);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "GID interactive input failed.\n");
            goto done;
        }
    } else {
        input_uctx->gid = uctx->gid;
    }

    if (uctx->gecos == NULL) {
        ret = seed_str_input(input_uctx, _("user comment (gecos)"),
                             &input_uctx->gecos);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Gecos interactive input failed.\n");
            goto done;
        }
    } else {
        input_uctx->gecos = talloc_strdup(input_uctx, uctx->gecos);
        if (input_uctx->gecos == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (uctx->home == NULL) {
        ret = seed_str_input(input_uctx, _("home directory"),
                             &input_uctx->home);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Home directory interactive input fialed.\n");
            goto done;
        }
    } else {
        input_uctx->home = talloc_strdup(input_uctx, uctx->home);
        if (input_uctx->home == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (uctx->shell == NULL) {
        ret = seed_str_input(input_uctx, _("user login shell"),
                             &input_uctx->shell);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Shell interactive input failed\n");
            goto done;
        }
    } else {
        input_uctx->shell = talloc_strdup(input_uctx, uctx->shell);
        if (input_uctx->shell == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

done:
    if (ret == EOK) {
        *_uctx = talloc_steal(mem_ctx, input_uctx);
    } else {
        ERROR("Interactive input failed.\n");
        talloc_zfree(input_uctx);
    }
    return ret;
}

static int seed_init(TALLOC_CTX *mem_ctx,
                     const int argc,
                     const char **argv,
                     struct seed_ctx **_sctx)
{
    TALLOC_CTX *tmp_ctx = NULL;
    int pc_debug = SSSDBG_TOOLS_DEFAULT;
    const char *pc_domain = NULL;
    const char *pc_name = NULL;
    uid_t pc_uid = 0;
    gid_t pc_gid = 0;
    const char *pc_gecos = NULL;
    const char *pc_home = NULL;
    const char *pc_shell = NULL;
    const char *pc_password_file = NULL;

    struct seed_ctx *sctx = NULL;

    int ret = EOK;

    poptContext pc = NULL;
    struct poptOption options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug, 0,
         _("The debug level to run with"), NULL },
        { "domain", 'D', POPT_ARG_STRING, &pc_domain, 0, _("Domain"), NULL },
        { "username", 'n', POPT_ARG_STRING, &pc_name, 0, _("Username"), NULL},
        { "uid",   'u', POPT_ARG_INT, &pc_uid, 0, _("User UID"), NULL },
        { "gid",   'g', POPT_ARG_INT, &pc_gid, 0, _("User GID"), NULL },
        { "gecos", 'c', POPT_ARG_STRING, &pc_gecos, 0,
         _("Comment string"), NULL},
        { "home",  'h', POPT_ARG_STRING, &pc_home, 0,
         _("Home directory"), NULL },
        { "shell", 's', POPT_ARG_STRING, &pc_shell, 0, _("Login Shell"), NULL },
        { "interactive", 'i', POPT_ARG_NONE, NULL, 'i',
         _("Use interactive mode to enter user data"), NULL },
        { "password-file", 'p', POPT_ARG_STRING, &pc_password_file, 0,
         _("File from which user's password is read "
           "(default is to prompt for password)"),NULL },
        POPT_TABLEEND
    };

    /* init contexts */
    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto fini;
    }

    sctx = talloc_zero(tmp_ctx, struct seed_ctx);
    if (sctx == NULL) {
        ERROR("Could not allocate tools context\n");
        ret = ENOMEM;
        goto fini;
    }

    sctx->uctx = talloc_zero(sctx, struct user_ctx);
    if (sctx->uctx == NULL) {
        ERROR("Could not allocate user data context\n");
        ret = ENOMEM;
        goto fini;
    }

    debug_prg_name = argv[0];
    ret = set_locale();
    if (ret != EOK) {
        ERROR("set_locale failed (%d): %s\n", ret, strerror(ret));
        ret = EINVAL;
        goto fini;
    }

    /* parse arguments */
    pc = poptGetContext(NULL, argc, argv, options, 0);
    if (argc < 2) {
        poptPrintUsage(pc,stderr,0);
        ret = EINVAL;
        goto fini;
    }

    poptSetOtherOptionHelp(pc, "[OPTIONS] -D <domain> -n <username>");
    while ((ret = poptGetNextOpt(pc)) > 0) {
        switch (ret) {
            case 'i':
                DEBUG(SSSDBG_TRACE_INTERNAL, "Interactive mode selected\n");
                sctx->interact = true;
                break;
        }
    }

    if (ret != -1) {
        BAD_POPT_PARAMS(pc, poptStrerror(ret), ret, fini);
    }

    DEBUG_CLI_INIT(pc_debug);

    CHECK_ROOT(ret, argv[0]);

    /* check username provided */
    if (pc_name == NULL) {
        BAD_POPT_PARAMS(pc, _("Username must be specified\n"), ret, fini);
    }

    /* check domain is provided */
    if (pc_domain == NULL) {
        BAD_POPT_PARAMS(pc, _("Domain must be specified.\n"), ret, fini);
    }

    sctx->uctx->domain_name = talloc_strdup(sctx->uctx, pc_domain);
    if (sctx->uctx->domain_name == NULL) {
        ret = ENOMEM;
        goto fini;
    }

    sctx->uctx->name = sss_create_internal_fqname(sctx->uctx,
                                                  pc_name, pc_domain);
    if (sctx->uctx->name == NULL) {
        ret = ENOMEM;
        goto fini;
    }

    poptFreeContext(pc);

    ret = EOK;

    /* copy all information provided from popt */
    sctx->uctx->uid = pc_uid;
    sctx->uctx->gid = pc_gid;
    if (pc_gecos != NULL) {
        sctx->uctx->gecos = talloc_strdup(sctx->uctx, pc_gecos);
        if (sctx->uctx->gecos == NULL) {
            ret = ENOMEM;
            goto fini;
        }
    }
    if (pc_home != NULL) {
        sctx->uctx->home = talloc_strdup(sctx->uctx, pc_home);
        if (sctx->uctx->home == NULL) {
            ret = ENOMEM;
            goto fini;
        }
    }
    if (pc_shell != NULL) {
        sctx->uctx->shell = talloc_strdup(sctx->uctx, pc_shell);
        if (sctx->uctx->shell == NULL) {
            ret = ENOMEM;
            goto fini;
        }
    }

    /* check if password file provided */
    if (pc_password_file != NULL) {
        sctx->password_file = talloc_strdup(sctx, pc_password_file);
        if (sctx->password_file == NULL) {
            ret = ENOMEM;
            goto fini;
        }
        sctx->password_method = PASS_FILE;
    } else {
        sctx->password_method = PASS_PROMPT;
    }

    *_sctx = talloc_steal(mem_ctx, sctx);

fini:
    talloc_free(tmp_ctx);
    return ret;
}

static int seed_init_db(TALLOC_CTX *mem_ctx,
                        const char *domain_name,
                        struct confdb_ctx **_confdb,
                        struct sss_domain_info **_domain,
                        struct sysdb_ctx **_sysdb)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct confdb_ctx *confdb = NULL;
    struct sss_domain_info *domain = NULL;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sss_tool_confdb_init(tmp_ctx, &confdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not initialize connection to the confdb\n");
        ERROR("Could not initialize connection to the confdb\n");
        goto done;
    }

    ret = sssd_domain_init(tmp_ctx, confdb, domain_name, DB_PATH, &domain);
    if (ret != EOK) {
        SYSDB_VERSION_ERROR(ret);
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not initialize connection to domain '%s' in sysdb.%s\n",
               domain_name, ret == ENOENT ? " Domain not found." : "");
        ERROR("Could not initialize connection to domain '%1$s' in sysdb.%2$s\n",
              domain_name, ret == ENOENT ? " Domain not found." : "");

        goto done;
    }

    *_confdb = talloc_steal(mem_ctx, confdb);
    *_domain = domain;
    *_sysdb = domain->sysdb;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int seed_domain_user_info(const char *name,
                                 struct sss_domain_info *domain,
                                 bool *is_cached)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct passwd *passwd = NULL;
    struct ldb_result *res = NULL;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    errno = 0;
    passwd = getpwnam(name);
    if (passwd == NULL) {
        ret = errno;
        DEBUG(SSSDBG_MINOR_FAILURE, "getpwnam failed [%d] [%s]\n",
                                     ret, strerror(ret));
        goto done;
    }

    /* look for user in cache */
    ret = sysdb_getpwnam(tmp_ctx, domain, name, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Couldn't lookup user (%s) in the cache\n", name);
        goto done;
    }

    if (res->count == 0) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "User (%s) wasn't found in the cache\n", name);
        *is_cached = false;
        ret = ENOENT;
        goto done;
    } else if (res->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Multiple user (%s) entries were found in the cache\n", name);
        ret = EINVAL;
        goto done;
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL, "User found in cache\n");
        *is_cached = true;

        errno = 0;
        ret = initgroups(name, passwd->pw_gid);
        if (ret != EOK) {
            ret = errno;
            DEBUG(SSSDBG_MINOR_FAILURE, "initgroups failed [%d] [%s]\n",
                                         ret, strerror(ret));
            goto done;
        }
    }

done:
    if (ret == ENOMEM) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to allocate user information\n");
    }
    talloc_zfree(tmp_ctx);
    return ret;
}

static int seed_cache_user(struct seed_ctx *sctx)
{
    bool in_transaction = false;
    int ret = EOK;
    errno_t sret;

    ret = sysdb_transaction_start(sctx->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb transaction start failure\n");
        goto done;
    }

    in_transaction = true;

    if (sctx->user_cached == false) {
        ret = sysdb_add_user(sctx->domain, sctx->uctx->name,
                             sctx->uctx->uid, sctx->uctx->gid,
                             sctx->uctx->gecos, sctx->uctx->home,
                             sctx->uctx->shell, NULL, NULL, 0, 0);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to add user to the cache. (%d)[%s]\n",
                   ret, strerror(ret));
            ERROR("Failed to create user cache entry\n");
            goto done;
        }
    }

    ret = sysdb_cache_password(sctx->domain, sctx->uctx->name,
                               sctx->uctx->password);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to cache password. (%d)[%s]\n",
                                  ret, strerror(ret));
        ERROR("Failed to cache password\n");
        goto done;
    }

    ret = sysdb_transaction_commit(sctx->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb transaction commit failure\n");
        goto done;
    }

    in_transaction = false;

done:
    if (in_transaction == true) {
        sret = sysdb_transaction_cancel(sctx->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to cancel transaction\n");
        }
    }

    return ret;
}

int main(int argc, const char **argv)
{
    struct seed_ctx *sctx = NULL;
    struct user_ctx *input_uctx = NULL;
    int ret = EOK;

    /* initialize seed context and parse options */
    ret = seed_init(sctx, argc, argv, &sctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,"Seed init failed [%d][%s]\n",
                                 ret, strerror(ret));
        goto done;
    }

    /* set up confdb,sysdb and domain */
    ret = seed_init_db(sctx, sctx->uctx->domain_name, &sctx->confdb,
                       &sctx->domain, &sctx->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to initialize db and domain\n");
        goto done;
    }

    /* get user info from domain */
    ret = seed_domain_user_info(sctx->uctx->name,
                                sctx->domain, &sctx->user_cached);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed lookup of user [%s] in domain [%s]\n",
                                  sctx->uctx->name, sctx->uctx->domain_name);
    }

    /* interactive mode to fill in user information */
    if (sctx->interact == true) {
        if (sctx->user_cached == true) {
            ERROR("User entry already exists in the cache.\n");
            ret = EEXIST;
            goto done;
        } else {
            ret = seed_interactive_input(sctx, sctx->uctx, &input_uctx);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Failed to get seed input.\n");
                ret = EINVAL;
                goto done;
            }
            talloc_zfree(sctx->uctx);
            sctx->uctx = input_uctx;
        }
    }

    if (sctx->user_cached == false) {
        if (sctx->uctx->uid == 0 || sctx->uctx->gid == 0) {
            /* require username, UID, and GID to continue */
            DEBUG(SSSDBG_MINOR_FAILURE, "Not enough information provided\n");
            ERROR("UID and primary GID not provided.\n");
            ret = EINVAL;
            goto done;
        }
    }

    /* password input */
    if (sctx->password_method == PASS_FILE) {
        ret = seed_password_input_file(sctx->uctx, sctx->password_file,
                                       &sctx->uctx->password);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Password input failure\n");
            goto done;
        }
    } else {
        ret = seed_password_input_prompt(sctx->uctx, &sctx->uctx->password);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Password input failure\n");
            goto done;
        }
    }

    /* Add user info and password to sysdb cache */
    ret = seed_cache_user(sctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Failed to modify cache.\n");
        goto done;
    } else {
        if (sctx->user_cached == false) {
            PRINT("User cache entry created for %1$s\n", sctx->uctx->name);
        }
        PRINT("Temporary password added to cache entry for %1$s\n",
              sctx->uctx->name);
    }

done:
    talloc_zfree(sctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Exit error: [%d] [%s]\n",
                                      ret, strerror(ret));
        ret = EXIT_FAILURE;
    } else {
        ret = EXIT_SUCCESS;
    }
    exit(ret);
}
