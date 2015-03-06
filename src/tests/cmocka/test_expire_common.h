/*
    Authors:
        Pavel Reichl <preichl@redhat.com>

    Copyright (C) 2015 Red Hat

    SSSD tests: Tests for password expiration related functionality

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

#ifndef __TEST_EXPIRE_COMMON_H
#define __TEST_EXPIRE_COMMON_H

struct expire_test_ctx
{
    char *past_time;
    char *future_time;
    char *invalid_format;
    char *invalid_longer_format;
};

int expire_test_setup(void **state);
int expire_test_teardown(void **state);
void expire_test_tz(const char* tz, void (*f)(void*, void*), void *in,
                    void *_out);

#endif /* __TEST_EXPIRE_COMMON_H */
