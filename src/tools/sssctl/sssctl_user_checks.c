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

#include "lib/sifp/sss_sifp.h"
#include "util/util.h"
#include "tools/common/sss_tools.h"
#include "tools/sssctl/sssctl.h"

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

static int get_ifp_user(const char *user)
{
    sss_sifp_ctx *sifp;
    sss_sifp_error error;
    sss_sifp_object *user_obj;
    const char *tmp_str;
    uint32_t tmp_uint32;
    size_t c;

    struct ifp_user_attr {
        const char *name;
        bool is_string;
    } ifp_user_attr[] = {
        { "name", true },
        { "uidNumber", false },
        { "gidNumber", false },
        { "gecos", true },
        { "homeDirectory", true },
        { "loginShell", true },
        { NULL, false }
    };

    error = sss_sifp_init(&sifp);
    if (error != SSS_SIFP_OK) {
        fprintf(stderr, _("Unable to connect to the InfoPipe"));
        return EFAULT;
    }

    error = sss_sifp_fetch_user_by_name(sifp, user, &user_obj);
    if (error != SSS_SIFP_OK) {
        fprintf(stderr, _("Unable to get user object"));
        return EIO;
    }

    fprintf(stdout, _("SSSD InfoPipe user lookup result:\n"));
    for (c = 0; ifp_user_attr[c].name != NULL; c++) {
        if (ifp_user_attr[c].is_string) {
            error = sss_sifp_find_attr_as_string(user_obj->attrs,
                                                 ifp_user_attr[c].name,
                                                 &tmp_str);
        } else {
            error = sss_sifp_find_attr_as_uint32(user_obj->attrs,
                                                 ifp_user_attr[c].name,
                                                 &tmp_uint32);
        }
        if (error != SSS_SIFP_OK) {
            fprintf(stderr, _("Unable to get user name attr"));
            return EIO;
        }

        if (ifp_user_attr[c].is_string) {
            fprintf(stdout, " - %s: %s\n", ifp_user_attr[c].name, tmp_str);
        } else {
            fprintf(stdout, " - %s: %"PRIu32"\n", ifp_user_attr[c].name,
                                                  tmp_uint32);
        }
    }
    fprintf(stdout, "\n");

    sss_sifp_free_object(sifp, &user_obj);
    sss_sifp_free(&sifp);
    return 0;
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
        fprintf(stderr, _("dlopen failed with [%s].\n"), dlerror());
        ret = EIO;
        goto done;
    }

    sss_getpwnam_r = dlsym(dl_handle, "_nss_sss_getpwnam_r");
    if (sss_getpwnam_r == NULL) {
        fprintf(stderr, _("dlsym failed with [%s].\n"), dlerror());
        ret = EIO;
        goto done;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = malloc(buflen);
    if (buffer == NULL) {
        fprintf(stderr, _("malloc failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    status = sss_getpwnam_r(user, &pwd, buffer, buflen, &nss_errno);
    if (status != NSS_STATUS_SUCCESS) {
        fprintf(stderr, _("sss_getpwnam_r failed with [%d].\n"), status);
        ret = EIO;
        goto done;
    }

    fprintf(stdout, _("SSSD nss user lookup result:\n"));
    fprintf(stdout, _(" - user name: %s\n"), pwd.pw_name);
    fprintf(stdout, _(" - user id: %d\n"), pwd.pw_uid);
    fprintf(stdout, _(" - group id: %d\n"), pwd.pw_gid);
    fprintf(stdout, _(" - gecos: %s\n"), pwd.pw_gecos);
    fprintf(stdout, _(" - home directory: %s\n"), pwd.pw_dir);
    fprintf(stdout, _(" - shell: %s\n\n"), pwd.pw_shell);

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
                           &user, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    fprintf(stdout, _("user: %s\naction: %s\nservice: %s\n\n"),
                    user, action, service);

    if (*user != '\0') {
        ret = sss_getpwnam_check(user);
        if (ret != 0) {
            fprintf(stderr, _("User name lookup with [%s] failed.\n"), user);
        }

        ret = get_ifp_user(user);
        if (ret != 0) {
            fprintf(stderr, _("InfoPipe User lookup with [%s] failed.\n"),
                            user);
        }
    }

    ret = pam_start(service, user, &conv, &pamh);
    if (ret != PAM_SUCCESS) {
        fprintf(stderr, _("pam_start failed: %s\n"), pam_strerror(pamh, ret));
        return 1;
    }

    if ( strncmp(action, "auth", 4)== 0 ) {
        fprintf(stdout, _("testing pam_authenticate\n\n"));
        ret = pam_authenticate(pamh, 0);
        pret = pam_get_item(pamh, PAM_USER, (const void **) &pam_user);
        if (pret != PAM_SUCCESS) {
            fprintf(stderr, _("pam_get_item failed: %s\n"), pam_strerror(pamh,
                                                                         pret));
            pam_user = "- not available -";
        }
        fprintf(stderr, _("pam_authenticate for user [%s]: %s\n\n"), pam_user,
                                                       pam_strerror(pamh, ret));
    } else if ( strncmp(action, "chau", 4)== 0 ) {
        fprintf(stdout, _("testing pam_chauthtok\n\n"));
        ret = pam_chauthtok(pamh, 0);
        fprintf(stderr, _("pam_chauthtok: %s\n\n"), pam_strerror(pamh, ret));
    } else if ( strncmp(action, "acct", 4)== 0 ) {
        fprintf(stdout, _("testing pam_acct_mgmt\n\n"));
        ret = pam_acct_mgmt(pamh, 0);
        fprintf(stderr, _("pam_acct_mgmt: %s\n\n"), pam_strerror(pamh, ret));
    } else if ( strncmp(action, "setc", 4)== 0 ) {
        fprintf(stdout, _("testing pam_setcred\n\n"));
        ret = pam_setcred(pamh, 0);
        fprintf(stderr, _("pam_setcred: [%s]\n\n"), pam_strerror(pamh, ret));
    } else if ( strncmp(action, "open", 4)== 0 ) {
        fprintf(stdout, _("testing pam_open_session\n\n"));
        ret = pam_open_session(pamh, 0);
        fprintf(stderr, _("pam_open_session: %s\n\n"), pam_strerror(pamh, ret));
    } else if ( strncmp(action, "clos", 4)== 0 ) {
        fprintf(stdout, _("testing pam_close_session\n\n"));
        ret = pam_close_session(pamh, 0);
        fprintf(stderr, _("pam_close_session: %s\n\n"),
                        pam_strerror(pamh, ret));
    } else {
        fprintf(stderr, _("unknown action\n"));
    }

    fprintf(stderr, _("PAM Environment:\n"));
    pam_env = pam_getenvlist(pamh);
    if (pam_env != NULL && pam_env[0] != NULL) {
        for (c = 0; pam_env[c] != NULL; c++) {
            fprintf(stderr, " - %s\n", pam_env[c]);
            free(pam_env[c]);
        }
    } else {
        fprintf(stderr, _(" - no env -\n"));
    }
    free(pam_env);

    pam_end(pamh, ret);

    return 0;
}
