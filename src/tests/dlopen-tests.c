/*
    SSSD

    debug-tests.c

    Authors:
        Simo Sorce <simo@redhat.com>

    Copyright (C) 2013 Red Hat

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

#define _GNU_SOURCE
#include <stdbool.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <check.h>
#include "tests/common.h"

#define LIBPFX ABS_BUILD_DIR"/.libs/"

struct so {
    const char *name;
    const char *libs[6];
} so[] = {
    { "libsss_debug.so", { LIBPFX"libsss_debug.so", NULL } },
    { "libipa_hbac.so", { LIBPFX"libipa_hbac.so", NULL } },
    { "libsss_idmap.so", { LIBPFX"libsss_idmap.so", NULL } },
    { "libsss_nss_idmap.so", { LIBPFX"libsss_nss_idmap.so", NULL } },
    { "libnss_sss.so", { LIBPFX"libnss_sss.so", NULL } },
    { "pam_sss.so", { LIBPFX"pam_sss.so", NULL } },
#ifdef BUILD_IFP
    { "libsss_simpleifp.so", { LIBPFX"libsss_simpleifp.so", NULL } },
#endif /* BUILD_IFP */
#ifdef BUILD_SUDO
    { "libsss_sudo.so", { LIBPFX"libsss_sudo.so", NULL } },
#endif
#ifdef BUILD_AUTOFS
    { "libsss_autofs.so", { LIBPFX"libsss_autofs.so", NULL } },
#endif
#ifdef HAVE_KRB5_LOCATOR_PLUGIN
    { "sssd_krb5_locator_plugin.so", { LIBPFX"sssd_krb5_locator_plugin.so",
                                       NULL } },
#endif
#ifdef HAVE_PAC_RESPONDER
    { "sssd_pac_plugin.so", { LIBPFX"sssd_pac_plugin.so", NULL } },
#endif
#ifdef HAVE_CIFS_IDMAP_PLUGIN
    { "cifs_idmap_sss.so", { LIBPFX"cifs_idmap_sss.so", NULL } },
#endif
    { "memberof.so", { LIBPFX"memberof.so", NULL } },
    { "libsss_child.so", { "libtevent.so",
                           LIBPFX"libsss_debug.so",
                           LIBPFX"libsss_crypt.so",
                           LIBPFX"libsss_util.so",
                           LIBPFX"libsss_child.so", NULL } },
    { "libsss_crypt.so", { "libtalloc.so",
                           LIBPFX"libsss_debug.so",
                           LIBPFX"libsss_crypt.so", NULL } },
    { "libsss_util.so", { "libtalloc.so",
                           LIBPFX"libsss_debug.so",
                           LIBPFX"libsss_crypt.so",
                           LIBPFX"libsss_util.so", NULL } },
    { "libsss_simple.so", { LIBPFX"libdlopen_test_providers.so",
                            LIBPFX"libsss_simple.so", NULL } },
#ifdef BUILD_SAMBA
    { "libsss_ad.so", { LIBPFX"libdlopen_test_providers.so",
                        LIBPFX"libsss_ad.so", NULL } },
    { "libsss_ipa.so", { LIBPFX"libdlopen_test_providers.so",
                         LIBPFX"libsss_ipa.so", NULL } },
#endif /* BUILD_SAMBA */
    { "libsss_krb5.so", { LIBPFX"libdlopen_test_providers.so",
                          LIBPFX"libsss_krb5.so", NULL } },
    { "libsss_krb5_common.so", { LIBPFX"libdlopen_test_providers.so",
                                 LIBPFX"libsss_krb5_common.so", NULL } },
    { "libsss_ldap.so", { LIBPFX"libdlopen_test_providers.so",
                          LIBPFX"libsss_ldap.so", NULL } },
    { "libsss_ldap_common.so", { LIBPFX"libdlopen_test_providers.so",
                                 LIBPFX"libsss_ldap_common.so", NULL } },
    { "libsss_proxy.so", { LIBPFX"libdlopen_test_providers.so",
                           LIBPFX"libsss_proxy.so", NULL } },
    { "libdlopen_test_providers.so", { LIBPFX"libdlopen_test_providers.so",
                                       NULL } },
#ifdef HAVE_PYTHON_BINDINGS
    { "pyhbac.so", { LIBPFX"pyhbac.so", NULL } },
    { "pysss.so", { LIBPFX"pysss.so", NULL } },
    { "pysss_murmur.so", { LIBPFX"pysss_murmur.so", NULL } },
    { "pysss_nss_idmap.so", { LIBPFX"pysss_nss_idmap.so", NULL } },
#endif
#ifdef HAVE_CONFIG_LIB
    { "libsss_config.so", { LIBPFX"libsss_config.so", NULL } },
#endif
    { NULL }
};

static bool recursive_dlopen(const char **name, int round, char **errmsg)
{
    void *handle;
    bool ok;

    *errmsg = NULL;

    handle = dlopen(name[round], RTLD_GLOBAL|RTLD_NOW);
    if (!handle) {
        if (asprintf(errmsg, "dlopen() failed: %s", dlerror()) == -1)
            *errmsg = NULL;
        return false;
    }

    round++;
    if (name[round]) {
        ok = recursive_dlopen(name, round, errmsg);
    } else {
        ok = true;
    }

    dlclose(handle);
    return ok;
}

START_TEST(test_dlopen_base)
{
    char *errmsg;
    bool ok;
    int i;

    for (i = 0; so[i].name != NULL; i++) {
        ok = recursive_dlopen(so[i].libs, 0, &errmsg);
        fail_unless(ok, "Error opening %s: [%s]", so[i].name, errmsg);
    }
}
END_TEST

Suite *dlopen_suite(void)
{
    Suite *s = suite_create("dlopen");

    TCase *tc_dlopen = tcase_create("dlopen");

    tcase_add_test(tc_dlopen, test_dlopen_base);
    tcase_set_timeout(tc_dlopen, 10);

    suite_add_tcase(s, tc_dlopen);

    return s;
}

int main(int argc, const char *argv[])
{
    int number_failed;

    Suite *s = dlopen_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    if (number_failed == 0)
        return EXIT_SUCCESS;

    return EXIT_FAILURE;
}
