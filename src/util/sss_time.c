/*
   SSSD - time utils

   Copyright (C) Sumit Bose <sbose@redhat.com> 2021

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

#include "util/util.h"

#define TV_TO_US(tv) ((tv).tv_sec * 1000000 + (tv).tv_usec)

uint64_t get_start_time()
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "gettimeofday failed.\n");
        return 0;
    }

    return TV_TO_US(tv);
}

const char *sss_format_time(uint64_t us)
{
    static char out[128];
    int ret;

    if (us == 0) {
        return "[- unavailable -]";
    }

    ret = snprintf(out, sizeof(out), "[%.3f] milliseconds", (double) us/1000);
    if (ret < 0 || ret >= sizeof(out)) {
        return "[- formatting error -]";
    }

    return out;
}

uint64_t get_spend_time_us(uint64_t st)
{
    struct timeval tv;
    uint64_t time_now;

    if (st == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing start time.\n");
        return 0;
    }

    if (gettimeofday(&tv, NULL) != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "gettimeofday failed.\n");
        return 0;
    }

    time_now = TV_TO_US(tv);

    if (st > time_now) {
        DEBUG(SSSDBG_OP_FAILURE, "Start time in future.\n");
        return 0;
    }

    return time_now - st;
}
