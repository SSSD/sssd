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
#include "tools/sss_sync_ops.h"
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
    struct sysdb_ctx *sysdb;

    struct user_ctx *uctx;

    char *password_file;
    enum seed_pass_method password_method;

    bool interact;
    bool user_cached;
};


static int seed_prompt(const char *req)
{
    size_t len = 0;
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
           DEBUG(SSSDBG_CRIT_FAILURE, ("write failed [%d][%s].\n",
                                       ret, strerror(ret)));
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
            DEBUG(SSSDBG_CRIT_FAILURE, ("read failed [%d][%s].\n",
                                        ret, strerror(ret)));
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
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to allocate input\n"));
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
            DEBUG(SSSDBG_CRIT_FAILURE, ("read failed [%d][%s].\n",
                                        ret, strerror(ret)));
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
            DEBUG(SSSDBG_OP_FAILURE, ("strtoll failed on [%s]: [%d][%s].\n",
                                      (char *)buf, ret, strerror(ret)));
            return ret;
        }
        if (*endptr != '\0') {
            DEBUG(SSSDBG_MINOR_FAILURE, ("extra characters [%s] after "
                                         "ID [%d]\n", endptr, *_id_input));
        }
    } else {
        ret = EINVAL;
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to get %s input.\n", req));
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
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not allocate temp context\n"));
        ret = ENOMEM;
        goto done;
    }

    temp = getpass("Enter temporary password:");
    if (temp == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to get prompted password\n"));
        ret = EINVAL;
        goto done;
    }
    password = talloc_strdup(tmp_ctx, temp);
    if (password == NULL) {
        ret = ENOMEM;
        goto done;
    }

    talloc_set_destructor((TALLOC_CTX *)password, password_destructor);

    temp = getpass("Enter temporary password again:");
    if (temp == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to get prompted password\n"));
        ret = EINVAL;
        goto done;
    }

    if (strncmp(temp,password,strlen(password)) != 0) {
        ERROR("Passwords do not match\n");
        DEBUG(SSSDBG_MINOR_FAILURE, ("Provided passwords do not match\n"));
        ret = EINVAL;
        goto done;
    }

    *_password = talloc_steal(mem_ctx, password);

done:
    talloc_free(tmp_ctx);
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

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not allocate temp context\n"));
        ret = ENOMEM;
        goto done;
    }

    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to open password file "
                                    "[%s] [%d][%s]\n",
                                    filename, errno, strerror(errno)));
        ret = EINVAL;
        goto done;
    }

    errno = 0;
    len = sss_atomic_read_s(fd, buf, PASS_MAX);
    if (len == -1) {
        ret = errno;
        DEBUG(SSSDBG_MINOR_FAILURE, ("Failed to read password from file "
                                     "[%s] [%d][%s]\n",
                                     filename, ret, strerror(ret)));
        close(fd);
        goto done;
    }

    close(fd);
    buf[len] = '\0';

    password = talloc_strdup(tmp_ctx, (char *)buf);
    if (password == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *_password = talloc_steal(mem_ctx, password);

done:
    talloc_free(tmp_ctx);
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
                  ("Username interactive input failed.\n"));
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
            DEBUG(SSSDBG_MINOR_FAILURE, ("UID interactive input failed.\n"));
            goto done;
        }
    } else {
        input_uctx->uid = uctx->uid;
    }

    if (uctx->gid == 0) {
        ret = seed_id_input(_("GID"), &input_uctx->gid);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, ("GID interactive input failed.\n"));
            goto done;
        }
    } else {
        input_uctx->gid = uctx->gid;
    }

    if (uctx->gecos == NULL) {
        ret = seed_str_input(input_uctx, _("user comment (gecos)"),
                             &input_uctx->gecos);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, ("Gecos interactive input failed.\n"));
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
                  ("Home directory interactive input fialed.\n"));
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
            DEBUG(SSSDBG_MINOR_FAILURE, ("Shell interactive input failed\n"));
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
    int pc_debug = SSSDBG_DEFAULT;
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
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not allocate tools context\n"));
        ret = ENOMEM;
        goto fini;
    }

    sctx->uctx = talloc_zero(sctx, struct user_ctx);
    if (sctx->uctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not allocate user data context\n"));
        ret = ENOMEM;
        goto fini;
    }

    debug_prg_name = argv[0];
    debug_level = debug_convert_old_level(pc_debug);

    ret = set_locale();
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("set_locale failed (%d): %s\n",
                                    ret, strerror(ret)));
        ERROR("Error setting the locale\n");
        ret = EINVAL;
        goto fini;
    }

    CHECK_ROOT(ret, argv[0]);

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
                DEBUG(SSSDBG_TRACE_INTERNAL, ("Interactive mode selected\n"));
                sctx->interact = true;
                break;
        }
    }

    if (ret != -1) {
        BAD_POPT_PARAMS(pc, poptStrerror(ret), ret, fini);
    }

    /* check username provided */
    if (pc_name == NULL) {
        BAD_POPT_PARAMS(pc, _("Username must be specified\n"), ret, fini);
    }

    sctx->uctx->name = talloc_strdup(sctx->uctx, pc_name);
    if (sctx->uctx->name == NULL) {
        ret = ENOMEM;
        goto fini;
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
                        struct sysdb_ctx **_sysdb)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *confdb_path = NULL;
    struct confdb_ctx *confdb = NULL;
    struct sysdb_ctx *sysdb = NULL;
    struct sss_domain_info *domain = NULL;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* setup confdb */
    confdb_path = talloc_asprintf(tmp_ctx, "%s/%s", DB_PATH, CONFDB_FILE);
    if (confdb_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = confdb_init(tmp_ctx, &confdb, confdb_path);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not initialize connection to the confdb\n"));
        ERROR("Could not initialize connection to the confdb\n");
        goto done;
    }

    ret = sysdb_init_domain_and_sysdb(tmp_ctx, confdb, domain_name,
                                      DB_PATH, &domain, &sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Could not initialize connection to the sysdb\n"));
        ERROR("Could not initialize the connection to the sysdb\n");
        goto done;
    }

    *_sysdb = talloc_steal(mem_ctx, sysdb);
    *_confdb = talloc_steal(mem_ctx, confdb);

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int seed_domain_user_info(const char *name,
                                 const char *domain_name,
                                 struct sysdb_ctx *sysdb,
                                 bool *is_cached)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *fq_name = NULL;
    struct passwd *passwd = NULL;
    struct ldb_result *res = NULL;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    fq_name = talloc_asprintf(tmp_ctx, "%s@%s", name, domain_name);
    if (fq_name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    errno = 0;
    passwd = getpwnam(fq_name);
    if (passwd == NULL) {
        ret = errno;
        DEBUG(SSSDBG_MINOR_FAILURE, ("getpwnam failed [%d] [%s]\n",
                                     ret, strerror(ret)));
        goto done;
    }

    /* look for user in cache */
    ret = sysdb_getpwnam(tmp_ctx, sysdb, name, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Couldn't lookup user (%s) in the cache\n", name));
        goto done;
    }

    if (res->count == 0) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              ("User (%s) wasn't found in the cache\n", name));
        *is_cached = false;
        ret = ENOENT;
        goto done;
    } else if (res->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Multiple user (%s) entries were found in the cache\n", name));
        ret = EINVAL;
        goto done;
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL, ("User found in cache\n"));
        *is_cached = true;

        errno = 0;
        ret = initgroups(fq_name, passwd->pw_gid);
        if (ret != EOK) {
            ret = errno;
            DEBUG(SSSDBG_MINOR_FAILURE, ("initgroups failed [%d] [%s]\n",
                                         ret, strerror(ret)));
            goto done;
        }
    }

done:
    if (ret == ENOMEM) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to allocate user information\n"));
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
        DEBUG(SSSDBG_CRIT_FAILURE, ("sysdb transaction start failure\n"));
        goto done;
    }

    in_transaction = true;

    if (sctx->user_cached == false) {
        ret = sysdb_add_user(sctx->sysdb, sctx->uctx->name,
                             sctx->uctx->uid, sctx->uctx->gid,
                             sctx->uctx->gecos, sctx->uctx->home,
                             sctx->uctx->shell, NULL, 0, 0);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Failed to add user to the cache. (%d)[%s]\n",
                   ret, strerror(ret)));
            ERROR("Failed to create user cache entry\n");
            goto done;
        }
    }

    ret = sysdb_cache_password(sctx->sysdb, sctx->uctx->name,
                               sctx->uctx->password);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to cache password. (%d)[%s]\n",
                                  ret, strerror(ret)));
        ERROR("Failed to cache password\n");
        goto done;
    }

    ret = sysdb_transaction_commit(sctx->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("sysdb transaction commit failure\n"));
        goto done;
    }

    in_transaction = false;

done:
    if (in_transaction == true) {
        sret = sysdb_transaction_cancel(sctx->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Failed to cancel transaction\n"));
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
        DEBUG(SSSDBG_OP_FAILURE,("Seed init failed [%d][%d]\n",
                                 ret, strerror(ret)));
        goto done;
    }

    /* set up confdb,sysdb and domain */
    ret = seed_init_db(sctx, sctx->uctx->domain_name, &sctx->confdb,
                       &sctx->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to initialize db and domain\n"));
        goto done;
    }

    /* get user info from domain */
    ret = seed_domain_user_info(sctx->uctx->name, sctx->uctx->domain_name,
                                sctx->sysdb, &sctx->user_cached);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed lookup of user [%s] in domain [%s]\n",
                                  sctx->uctx->name, sctx->uctx->domain_name));
    }

    /* interactive mode to fill in user information */
    if (sctx->interact == true) {
        if (sctx->user_cached == true) {
            ERROR(_("User entry already exists in the cache.\n"));
            ret = EEXIST;
            goto done;
        } else {
            ret = seed_interactive_input(sctx, sctx->uctx, &input_uctx);
            if (ret != EOK) {
                DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to get seed input.\n"));
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
            DEBUG(SSSDBG_MINOR_FAILURE, ("Not enough information provided\n"));
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
            DEBUG(SSSDBG_CRIT_FAILURE, ("Password input failure\n"));
            goto done;
        }
    } else {
        ret = seed_password_input_prompt(sctx->uctx, &sctx->uctx->password);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Password input failure\n"));
            goto done;
        }
    }

    /* Add user info and password to sysdb cache */
    ret = seed_cache_user(sctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("Failed to modify cache.\n"));
        goto done;
    } else {
        if (sctx->user_cached == false) {
            printf(_("User cache entry created for %1$s\n"), sctx->uctx->name);
        }
        printf(_("Temporary password added to cache entry for %1$s\n"),
                 sctx->uctx->name);
    }

done:
    talloc_zfree(sctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_INTERNAL, ("Exit error: [%d] [%s]\n",
                                      ret, strerror(ret)));
        ret = EXIT_FAILURE;
    } else {
        ret = EXIT_SUCCESS;
    }
    exit(ret);
}
