/*
    SSSD

    wbc-calls - Tests for selected libwbclient calls

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2015 Red Hat

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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"

#include "sss_client/libwbclient/wbclient_sssd.h"
#include "sss_client/idmap/sss_nss_idmap.h"

struct wbcDomainSid test_sid = {1, 5, {0, 0, 0, 0, 0, 5},
                                {21, 2127521184, 1604012920, 1887927527, 72713,
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

int __wrap_sss_nss_getnamebysid(const char *sid, char **fq_name,
                                enum sss_id_type *type)
{
    *fq_name = strdup("name@domain");
    assert_non_null(*fq_name);
    *type = SSS_ID_TYPE_UID;

    return EOK;
}

void test_wbcLookupSid(void **state)
{
    wbcErr wbc_status;
    char *pdomain;
    char *pname;
    enum wbcSidType pname_type;

    wbc_status = wbcLookupSid(NULL, NULL, NULL, NULL);
    assert_int_equal(wbc_status, WBC_ERR_INVALID_SID);

    wbc_status = wbcLookupSid(&test_sid, NULL, NULL, NULL);
    assert_int_equal(wbc_status, WBC_ERR_SUCCESS);

    wbc_status = wbcLookupSid(&test_sid, &pdomain, NULL, NULL);
    assert_int_equal(wbc_status, WBC_ERR_SUCCESS);
    assert_string_equal(pdomain, "domain");
    wbcFreeMemory(pdomain);

    wbc_status = wbcLookupSid(&test_sid, NULL, &pname, NULL);
    assert_int_equal(wbc_status, WBC_ERR_SUCCESS);
    assert_string_equal(pname, "name");
    wbcFreeMemory(pname);

    wbc_status = wbcLookupSid(&test_sid, NULL, NULL, &pname_type);
    assert_int_equal(wbc_status, WBC_ERR_SUCCESS);
    assert_int_equal(pname_type, WBC_SID_NAME_USER);

    wbc_status = wbcLookupSid(&test_sid, &pdomain, &pname, &pname_type);
    assert_int_equal(wbc_status, WBC_ERR_SUCCESS);
    assert_string_equal(pdomain, "domain");
    assert_string_equal(pname, "name");
    assert_int_equal(pname_type, WBC_SID_NAME_USER);
    wbcFreeMemory(pdomain);
    wbcFreeMemory(pname);
}

int main(int argc, const char *argv[])
{
    int rv;
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_wbcLookupSid),
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while ((opt = poptGetNextOpt(pc)) != -1) {
        switch (opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    DEBUG_CLI_INIT(debug_level);

    tests_set_cwd();
    rv = cmocka_run_group_tests(tests, NULL, NULL);

    return rv;
}
