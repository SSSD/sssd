#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

static struct pam_conv conv = {
    misc_conv,
    NULL
};

int main(int argc, char *argv[]) {

    pam_handle_t *pamh;
    char *user;
    char *action;
    int ret;

    if (argc == 1) {
        fprintf(stderr, "missing action and user name, using default\n");
        action = strdup("auth");
        user = strdup("dummy");
    } else if (argc == 2) {
        fprintf(stdout, "using first argument as action and default user name\n");
        action = strdup(argv[1]);
        user = strdup("dummy");
    } else {
        action = strdup(argv[1]);
        user = strdup(argv[2]);
    }

    fprintf(stdout, "action: %s\nuser: %s\n", action,user);

    ret = pam_start("sss_test", user, &conv, &pamh);
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

    pam_end(pamh, ret);

    return 0;
}
