/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <pwd.h>
#include <nss.h>
#include <errno.h>
#include <inttypes.h>

#include <security/pam_appl.h>

#include "util/util.h"
#include "tools/common/sss_tools.h"
#include "tools/sssctl/sssctl.h"
#include "responder/ifp/ifp_iface/ifp_iface_sync.h"

#ifdef HAVE_SECURITY_PAM_MISC_H
# include <security/pam_misc.h>
#elif defined(HAVE_SECURITY_OPENPAM_H)
# include <security/openpam.h>
#endif

#ifdef HAVE_SECURITY_PAM_MISC_H
static struct pam_conv conv = {
    misc_conv,
    NULL
};
#elif defined(HAVE_SECURITY_OPENPAM_H)
static struct pam_conv conv = {
    openpam_ttyconv,
    NULL
};
#else
# error "Missing text based pam conversation function"
#endif

#define DEFAULT_ACTION "acct"
#define DEFAULT_SERVICE "system-auth"

#define DEFAULT_BUFSIZE 4096

#define PRINT_IFP_PROPERTY(all, name, fmt) do { \
    if (all->name.is_set) { \
        fprintf(stdout, " - %s: %" fmt "\n", #name, user->name.value); \
    } else { \
        fprintf(stdout, " - %s: not set\n", #name); \
    } \
} while (0)

static errno_t get_ifp_user(const char *username)
{
    TALLOC_CTX *tmp_ctx;
    struct sbus_sync_connection *conn;
    struct sbus_all_ifp_user *user;
    const char *path;
    struct hash_iter_context_t *extra_iter;
    char **extra_values;
    hash_entry_t *extra_entry;
    int extra_idx;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    conn = sbus_sync_connect_system(tmp_ctx, NULL);
    if (conn == NULL) {
        ERROR("Unable to connect to system bus!\n");
        ret = EIO;
        goto done;
    }

    ret = sbus_call_ifp_users_FindByName(tmp_ctx, conn, IFP_BUS, IFP_PATH_USERS,
              username, &path);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to find user by name [%d]: %s\n",
              ret, sss_strerror(ret));
        PRINT_IFP_WARNING(ret);
        goto done;
    }

    ret = sbus_getall_ifp_user(tmp_ctx, conn, IFP_BUS, path, &user);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get user properties [%d]: %s\n",
              ret, sss_strerror(ret));
        PRINT_IFP_WARNING(ret);
        goto done;
    }

    PRINT("SSSD InfoPipe user lookup result:\n");
    PRINT_IFP_PROPERTY(user, name, "s");
    PRINT_IFP_PROPERTY(user, uidNumber, PRIu32);
    PRINT_IFP_PROPERTY(user, gidNumber, PRIu32);
    PRINT_IFP_PROPERTY(user, gecos, "s");
    PRINT_IFP_PROPERTY(user, homeDirectory, "s");
    PRINT_IFP_PROPERTY(user, loginShell, "s");

    /* print extra attributes */
    if (user->extraAttributes.is_set) {
        extra_iter = new_hash_iter_context(user->extraAttributes.value);
        if (extra_iter == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "new_hash_iter_context failed.\n");
            ret = EINVAL;
            goto done;
        }

        while ((extra_entry = extra_iter->next(extra_iter)) != NULL) {
            extra_values = extra_entry->value.ptr;
            for(extra_idx = 0; extra_values[extra_idx] != NULL; ++extra_idx) {
                fprintf(stdout, " - %s: %s\n", extra_entry->key.str, extra_values[extra_idx]);
            }
        }
    }

    fprintf(stdout, "\n");

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static int sss_getpwnam_check(const char *user)
{
    void *dl_handle = NULL;
    enum nss_status (*sss_getpwnam_r)(const char *name, struct passwd *result,
                                      char *buffer, size_t buflen,
                                      int *errnop);
    struct passwd pwd = { 0 };
    enum nss_status status;
    char *buffer = NULL;
    size_t buflen;
    int nss_errno;
    int ret;

    dl_handle = dlopen("libnss_sss.so.2", RTLD_NOW);
    if (dl_handle == NULL) {
        ERROR("dlopen failed with [%s].\n", dlerror());
        ret = EIO;
        goto done;
    }

    sss_getpwnam_r = dlsym(dl_handle, "_nss_sss_getpwnam_r");
    if (sss_getpwnam_r == NULL) {
        ERROR("dlsym failed with [%s].\n", dlerror());
        ret = EIO;
        goto done;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = malloc(buflen);
    if (buffer == NULL) {
        ERROR("malloc failed.\n");
        ret = ENOMEM;
        goto done;
    }

    status = sss_getpwnam_r(user, &pwd, buffer, buflen, &nss_errno);
    if (status != NSS_STATUS_SUCCESS) {
        ERROR("sss_getpwnam_r failed with [%d].\n", status);
        ret = EIO;
        goto done;
    }

    PRINT("SSSD nss user lookup result:\n");
    PRINT(" - user name: %s\n", pwd.pw_name);
    PRINT(" - user id: %d\n", pwd.pw_uid);
    PRINT(" - group id: %d\n", pwd.pw_gid);
    PRINT(" - gecos: %s\n", pwd.pw_gecos);
    PRINT(" - home directory: %s\n", pwd.pw_dir);
    PRINT(" - shell: %s\n\n", pwd.pw_shell);

    ret = 0;

done:
    if (dl_handle != NULL) {
        dlclose(dl_handle);
    }

    free(buffer);

    return ret;
}

errno_t sssctl_user_checks(struct sss_cmdline *cmdline,
                           struct sss_tool_ctx *tool_ctx,
                           void *pvt)
{

    pam_handle_t *pamh;
    const char *user = NULL;
    const char *action = DEFAULT_ACTION;
    const char *service = DEFAULT_SERVICE;
    int ret;
    int pret;
    const char *pam_user = NULL;
    size_t c;
    char **pam_env;

    /* Parse command line. */
    struct poptOption options[] = {
        { "action", 'a', POPT_ARG_STRING, &action, 0,
          _("PAM action [auth|acct|setc|chau|open|clos], default: "
            DEFAULT_ACTION), NULL },
        { "service", 's', POPT_ARG_STRING, &service, 0,
          _("PAM service, default: " DEFAULT_SERVICE), NULL },
        POPT_TABLEEND
    };

    ret = sss_tool_popt_ex(cmdline, options, SSS_TOOL_OPT_OPTIONAL,
                           NULL, NULL, "USERNAME", _("Specify user name."),
                           SSS_TOOL_OPT_REQUIRED, &user, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        goto done;
    }

    PRINT("user: %s\naction: %s\nservice: %s\n\n", user, action, service);

    if (*user != '\0') {
        ret = sss_getpwnam_check(user);
        if (ret != 0) {
            ERROR("User name lookup with [%s] failed.\n", user);
        }

        ret = get_ifp_user(user);
        if (ret != 0) {
            ERROR("InfoPipe User lookup with [%s] failed.\n", user);
        }
    }

    ret = pam_start(service, user, &conv, &pamh);
    if (ret != PAM_SUCCESS) {
        ERROR("pam_start failed: %s\n", pam_strerror(pamh, ret));
        ret = EPERM;
        goto done;
    }

    if ( strncmp(action, "auth", 4)== 0 ) {
        PRINT("testing pam_authenticate\n\n");
        ret = pam_authenticate(pamh, 0);
        pret = pam_get_item(pamh, PAM_USER, (const void **) &pam_user);
        if (pret != PAM_SUCCESS) {
            ERROR("pam_get_item failed: %s\n", pam_strerror(pamh, pret));
            pam_user = "- not available -";
        }
        ERROR("pam_authenticate for user [%s]: %s\n\n", pam_user,
                                                       pam_strerror(pamh, ret));
    } else if ( strncmp(action, "chau", 4)== 0 ) {
        PRINT("testing pam_chauthtok\n\n");
        ret = pam_chauthtok(pamh, 0);
        ERROR("pam_chauthtok: %s\n\n", pam_strerror(pamh, ret));
    } else if ( strncmp(action, "acct", 4)== 0 ) {
        PRINT("testing pam_acct_mgmt\n\n");
        ret = pam_acct_mgmt(pamh, 0);
        ERROR("pam_acct_mgmt: %s\n\n", pam_strerror(pamh, ret));
    } else if ( strncmp(action, "setc", 4)== 0 ) {
        PRINT("testing pam_setcred\n\n");
        ret = pam_setcred(pamh, 0);
        ERROR("pam_setcred: [%s]\n\n", pam_strerror(pamh, ret));
    } else if ( strncmp(action, "open", 4)== 0 ) {
        PRINT("testing pam_open_session\n\n");
        ret = pam_open_session(pamh, 0);
        ERROR("pam_open_session: %s\n\n", pam_strerror(pamh, ret));
    } else if ( strncmp(action, "clos", 4)== 0 ) {
        PRINT("testing pam_close_session\n\n");
        ret = pam_close_session(pamh, 0);
        ERROR("pam_close_session: %s\n\n", pam_strerror(pamh, ret));
    } else {
        ERROR("unknown action\n");
    }

    ERROR("PAM Environment:\n");
    pam_env = pam_getenvlist(pamh);
    if (pam_env != NULL && pam_env[0] != NULL) {
        for (c = 0; pam_env[c] != NULL; c++) {
            fprintf(stderr, " - %s\n", pam_env[c]);
            free(pam_env[c]);
        }
    } else {
        ERROR(" - no env -\n");
    }
    free(pam_env);

    pam_end(pamh, ret);
    ret = EOK;

done:
    free(discard_const(user));

    return ret;
}
