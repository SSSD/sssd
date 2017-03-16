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
        fprintf(stderr, "Unable to connect to the InfoPipe");
        return EFAULT;
    }

    error = sss_sifp_fetch_user_by_name(sifp, user, &user_obj);
    if (error != SSS_SIFP_OK) {
        fprintf(stderr, "Unable to get user object");
        return EIO;
    }

    fprintf(stdout, "SSSD InfoPipe user lookup result:\n");
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
            fprintf(stderr, "Unable to get user name attr");
            return EIO;
        }

        if (ifp_user_attr[c].is_string) {
            fprintf(stdout, " - %s: %s\n", ifp_user_attr[c].name, tmp_str);
        } else {
            fprintf(stdout, " - %s: %"PRIu32"\n", ifp_user_attr[c].name,
                                                  tmp_uint32);
        }
    }

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
        fprintf(stderr, "dlopen failed with [%s].\n", dlerror());
        ret = EIO;
        goto done;
    }

    sss_getpwnam_r = dlsym(dl_handle, "_nss_sss_getpwnam_r");
    if (sss_getpwnam_r == NULL) {
        fprintf(stderr, "dlsym failed with [%s].\n", dlerror());
        ret = EIO;
        goto done;
    }

    buflen = DEFAULT_BUFSIZE;
    buffer = malloc(buflen);
    if (buffer == NULL) {
        fprintf(stderr, "malloc failed.\n");
        ret = ENOMEM;
        goto done;
    }

    status = sss_getpwnam_r(user, &pwd, buffer, buflen, &nss_errno);
    if (status != NSS_STATUS_SUCCESS) {
        fprintf(stderr, "sss_getpwnam_r failed with [%d].\n", status);
        ret = EIO;
        goto done;
    }

    fprintf(stdout, "SSSD nss user lookup result:\n");
    fprintf(stdout, " - user name: %s\n", pwd.pw_name);
    fprintf(stdout, " - user id: %d\n", pwd.pw_uid);
    fprintf(stdout, " - group id: %d\n", pwd.pw_gid);
    fprintf(stdout, " - gecos: %s\n", pwd.pw_gecos);
    fprintf(stdout, " - home directory: %s\n", pwd.pw_dir);
    fprintf(stdout, " - shell: %s\n", pwd.pw_shell);

    ret = 0;

done:
    if (dl_handle != NULL) {
        dlclose(dl_handle);
    }

    free(buffer);

    return ret;
}

int main(int argc, char *argv[]) {

    pam_handle_t *pamh;
    char *user;
    char *action;
    char *service;
    int ret;
    size_t c;
    char **pam_env;

    if (argc == 1) {
        fprintf(stderr, "Usage: pam_test_client USERNAME "
                        "[auth|acct|setc|chau|open|clos] [pam_service]\n");
        return 0;
    } else if (argc == 2) {
        fprintf(stderr, "using first argument as user name and default action "
                        "and service\n");
    } else if (argc == 3) {
        fprintf(stderr, "using first argument as user name, second as action "
                        "and default service\n");
    }

    user = strdup(argv[1]);
    action = argc > 2 ? strdup(argv[2]) : strdup(DEFAULT_ACTION);
    service = argc > 3 ? strdup(argv[3]) : strdup(DEFAULT_SERVICE);

    if (action == NULL || user == NULL || service == NULL) {
        fprintf(stderr, "Out of memory!\n");
        return 1;
    }

    fprintf(stdout, "user: %s\naction: %s\nservice: %s\n",
                    user, action, service);

    if (*user != '\0') {
        ret = sss_getpwnam_check(user);
        if (ret != 0) {
            fprintf(stderr, "User name lookup with [%s] failed.\n", user);
        }

        ret = get_ifp_user(user);
        if (ret != 0) {
            fprintf(stderr, "InforPipe User lookup with [%s] failed.\n", user);
        }
    }

    ret = pam_start(service, user, &conv, &pamh);
    if (ret != PAM_SUCCESS) {
        fprintf(stderr, "pam_start failed: %s\n", pam_strerror(pamh, ret));
        return 1;
    }

    if ( strncmp(action, "auth", 4)== 0 ) {
        fprintf(stdout, "testing pam_authenticate\n");
        ret = pam_authenticate(pamh, 0);
        fprintf(stderr, "pam_authenticate: %s\n", pam_strerror(pamh, ret));
    } else if ( strncmp(action, "chau", 4)== 0 ) {
        fprintf(stdout, "testing pam_chauthtok\n");
        ret = pam_chauthtok(pamh, 0);
        fprintf(stderr, "pam_chauthtok: %s\n", pam_strerror(pamh, ret));
    } else if ( strncmp(action, "acct", 4)== 0 ) {
        fprintf(stdout, "testing pam_acct_mgmt\n");
        ret = pam_acct_mgmt(pamh, 0);
        fprintf(stderr, "pam_acct_mgmt: %s\n", pam_strerror(pamh, ret));
    } else if ( strncmp(action, "setc", 4)== 0 ) {
        fprintf(stdout, "testing pam_setcred\n");
        ret = pam_setcred(pamh, 0);
        fprintf(stderr, "pam_setcred: %d[%s]\n", ret, pam_strerror(pamh, ret));
    } else if ( strncmp(action, "open", 4)== 0 ) {
        fprintf(stdout, "testing pam_open_session\n");
        ret = pam_open_session(pamh, 0);
        fprintf(stderr, "pam_open_session: %s\n", pam_strerror(pamh, ret));
    } else if ( strncmp(action, "clos", 4)== 0 ) {
        fprintf(stdout, "testing pam_close_session\n");
        ret = pam_close_session(pamh, 0);
        fprintf(stderr, "pam_close_session: %s\n", pam_strerror(pamh, ret));
    } else {
        fprintf(stderr, "unknown action\n");
    }

    fprintf(stderr, "PAM Environment:\n");
    pam_env = pam_getenvlist(pamh);
    if (pam_env != NULL && pam_env[0] != NULL) {
        for (c = 0; pam_env[c] != NULL; c++) {
            fprintf(stderr, " - %s\n", pam_env[c]);
            free(pam_env[c]);
        }
    } else {
        fprintf(stderr, " - no env -\n");
    }
    free(pam_env);

    pam_end(pamh, ret);

    free(user);
    free(action);
    free(service);

    return 0;
}
