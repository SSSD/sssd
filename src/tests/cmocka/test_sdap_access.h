/*
    Authors:
        Alexey Kamenskiy <aleksey.kamensky@gmail.com>

    SSSD tests - sdap access tests

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

#ifndef TEST_SDAP_ACCESS_H
#define TEST_SDAP_ACCESS_H

struct test_sdap_access_rhost_ctx {
    struct ldb_message *user_no_rhost;
    struct ldb_message *user_allow_somehost;
    struct ldb_message *user_deny_somehost;
    struct ldb_message *user_allow_all;
    struct ldb_message *user_allow_all_deny_somehost;
    struct ldb_message *user_allow_all_allow_somehost_deny_somehost;
};

static int test_sdap_access_rhost_setup(void **state);
static int test_sdap_access_rhost_teardown(void **state);

#endif /* TEST_SDAP_ACCESS_H */
