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

#include "config.h"

#include <stdbool.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <check.h>
#include <dirent.h>
#include "tests/common_check.h"

#define LIBPFX ABS_BUILD_DIR "/" LT_OBJDIR

struct so {
    const char *name;
    const char *libs[6];
} so[] = {
    { "libsss_debug.so", { LIBPFX"libsss_debug.so", NULL } },
    { "libipa_hbac.so", { LIBPFX"libipa_hbac.so", NULL } },
    { "libsss_idmap.so", { LIBPFX"libsss_idmap.so", NULL } },
    { "libsss_nss_idmap.so", { LIBPFX"libsss_nss_idmap.so", NULL } },
    { "libnss_sss.so", { LIBPFX"libnss_sss.so", NULL } },
    { "libsss_certmap.so", { LIBPFX"libsss_certmap.so", NULL } },
    { "pam_sss.so", { LIBPFX"pam_sss.so", NULL } },
    { "pam_sss_gss.so", { LIBPFX"pam_sss_gss.so", NULL } },
#ifdef BUILD_SUDO
    { "libsss_sudo.so", { LIBPFX"libsss_sudo.so", NULL } },
#endif
#ifdef BUILD_AUTOFS
    { "libsss_autofs.so", { LIBPFX"libsss_autofs.so", NULL } },
#endif
#ifdef BUILD_SUBID
    { "libsubid_sss.so", { LIBPFX"libsubid_sss.so", NULL } },
#endif
#ifdef HAVE_KRB5_LOCATOR_PLUGIN
    { "sssd_krb5_locator_plugin.so", { LIBPFX"sssd_krb5_locator_plugin.so",
                                       NULL } },
#endif
#ifdef HAVE_KRB5_LOCALAUTH_PLUGIN
    { "sssd_krb5_localauth_plugin.so", { LIBPFX"sssd_krb5_localauth_plugin.so",
                                       NULL } },
#endif
    { "sssd_krb5_idp_plugin.so", { LIBPFX"sssd_krb5_idp_plugin.so", NULL } },
#ifdef BUILD_PASSKEY
    { "sssd_krb5_passkey_plugin.so", { LIBPFX"sssd_krb5_passkey_plugin.so", NULL } },
#endif
#ifdef HAVE_PAC_RESPONDER
    { "sssd_pac_plugin.so", { LIBPFX"sssd_pac_plugin.so", NULL } },
#endif
#ifdef HAVE_CIFS_IDMAP_PLUGIN
    { "cifs_idmap_sss.so", { LIBPFX"cifs_idmap_sss.so", NULL } },
#endif
    { "memberof.so", { LIBPFX"memberof.so", NULL } },
    { "libsss_child.so", { LIBPFX"libsss_util.so",
                           LIBPFX"libsss_child.so", NULL } },
    { "libsss_crypt.so", { LIBPFX"libsss_crypt.so", NULL } },
    { "libsss_cert.so", { LIBPFX"libsss_util.so",
                          LIBPFX"libsss_cert.so", NULL } },
    { "libsss_util.so", { LIBPFX"libsss_util.so", NULL } },
    { "libsss_sbus.so", {NULL} },
    { "libsss_sbus_sync.so", {NULL} },
    { "libsss_iface.so", {NULL} },
    { "libsss_iface_sync.so", {NULL} },
    { "libifp_iface.so", {NULL} },
    { "libifp_iface_sync.so", {NULL} },
    { "libsss_simple.so", { LIBPFX"libdlopen_test_providers.so",
                            LIBPFX"libsss_simple.so", NULL } },
#ifdef BUILD_SAMBA
    { "libsss_ad.so", { LIBPFX"libdlopen_test_providers.so",
                        LIBPFX"libsss_ad.so", NULL } },
    { "libsss_ipa.so", { LIBPFX"libdlopen_test_providers.so",
                         LIBPFX"libsss_ipa.so", NULL } },
    { "winbind_idmap_sss.so", { LIBPFX"libdlopen_test_winbind_idmap.so",
                                LIBPFX"winbind_idmap_sss.so", NULL } },
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
#ifdef BUILD_ID_PROVIDER_IDP
    { "libsss_idp.so", { LIBPFX"libdlopen_test_providers.so",
                         LIBPFX"libsss_idp.so", NULL } },
#endif /* BUILD_ID_PROVIDER_IDP */
    { "libsss_minimal.so", { LIBPFX"libdlopen_test_providers.so",
                             LIBPFX"libsss_minimal.so", NULL } },
#ifdef HAVE_PYTHON2_BINDINGS
    { "_py2hbac.so", { LIBPFX"_py2hbac.so", NULL } },
    { "_py2sss.so", { LIBPFX"_py2sss.so", NULL } },
    { "_py2sss_murmur.so", { LIBPFX"_py2sss_murmur.so", NULL } },
    { "_py2sss_nss_idmap.so", { LIBPFX"_py2sss_nss_idmap.so", NULL } },
#endif
#ifdef HAVE_PYTHON3_BINDINGS
#ifdef PYTHON_DLOPEN_LIB
    { "_py3hbac.so", { PYTHON_DLOPEN_LIB, LIBPFX"_py3hbac.so", NULL } },
    { "_py3sss.so", { PYTHON_DLOPEN_LIB, LIBPFX"_py3sss.so", NULL } },
    { "_py3sss_murmur.so", { PYTHON_DLOPEN_LIB, LIBPFX"_py3sss_murmur.so", NULL } },
    { "_py3sss_nss_idmap.so", { PYTHON_DLOPEN_LIB, LIBPFX"_py3sss_nss_idmap.so", NULL } },
#else
    { "_py3hbac.so", { LIBPFX"_py3hbac.so", NULL } },
    { "_py3sss.so", { LIBPFX"_py3sss.so", NULL } },
    { "_py3sss_murmur.so", { LIBPFX"_py3sss_murmur.so", NULL } },
    { "_py3sss_nss_idmap.so", { LIBPFX"_py3sss_nss_idmap.so", NULL } },
#endif
#endif
#ifdef BUILD_NFS_IDMAP
    { "sss.so", { LIBPFX"sss.so", NULL } },
#endif
    /* for testing purposes */
    { "libdlopen_test_providers.so", { LIBPFX"libdlopen_test_providers.so",
                                       NULL } },
#ifdef BUILD_SAMBA
    { "libdlopen_test_winbind_idmap.so",
      { LIBPFX"libdlopen_test_winbind_idmap.so", NULL } },
    { "libsss_ad_tests.so", { LIBPFX"libdlopen_test_providers.so",
                              LIBPFX"libsss_ad_tests.so", NULL } },
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

static int file_so_filter(const struct dirent *ent)
{
    char *suffix;

    suffix = rindex(ent->d_name, '.');
    if (suffix != NULL
            && strcmp(suffix, ".so") == 0
            && suffix[3] == '\0') {
        return 1;
    }

    return 0;
}

static char **get_so_files(size_t *_list_size)
{
    int n;
    struct dirent **namelist;
    char **libraries;

    n = scandir(LIBPFX, &namelist, file_so_filter, alphasort);
    ck_assert_msg(n > 0, "Failed to scan dirrectory: " LIBPFX);

    libraries = calloc(n + 1, sizeof(char *));

    for (int i = 0; i < n; ++i) {
        libraries[i] = strdup(namelist[i]->d_name);
        sss_ck_fail_if_msg(libraries[i] == NULL, "Failed to allocate memory");

        free(namelist[i]);
    }
    free(namelist);

    *_list_size = (size_t)n;
    return libraries;
}

static void remove_library_from_list(const char *library, char **list,
                                     size_t list_size)
{
    for (size_t i = 0; i < list_size; ++i) {
        if (list[i] != NULL && strcmp(library, list[i]) == 0) {
            /* found library need to be removed from list */
            free(list[i]);
            list[i] = NULL;
            return;
        }
    }

    ck_abort_msg("Cannot find expected library: %s", library);
}

START_TEST(test_dlopen_base)
{
    char *errmsg;
    bool ok;
    int i;
    size_t found_libraries_size;
    char **found_libraries = get_so_files(&found_libraries_size);
    bool unchecked_library = false;

    for (i = 0; so[i].name != NULL; i++) {
        ok = recursive_dlopen(so[i].libs, 0, &errmsg);
        ck_assert_msg(ok, "Error opening %s: [%s]", so[i].name, errmsg);

        remove_library_from_list(so[i].name, found_libraries,
                                 found_libraries_size);
    }

    for (i = 0; i < found_libraries_size; ++i) {
        if (found_libraries[i] != NULL) {
            printf("Unchecked library found: %s\n", found_libraries[i]);
            unchecked_library = true;
        }
    }
    free(found_libraries);

    sss_ck_fail_if_msg(unchecked_library, "Unchecked library found");
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
