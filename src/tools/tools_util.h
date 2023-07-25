/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2009 Red Hat

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


#ifndef __TOOLS_UTIL_H__
#define __TOOLS_UTIL_H__

#define BAD_POPT_PARAMS(pc, msg, val, label) do { \
        usage(pc, msg);                           \
        val = EXIT_FAILURE;                       \
        goto label;                               \
} while(0)

#define CHECK_ROOT(val, prg_name) do { \
    val = getuid(); \
    if (val != 0) { \
        DEBUG(SSSDBG_CRIT_FAILURE, "Running under %d, must be root\n", val); \
        ERROR("%1$s must be run as root\n", prg_name); \
        val = EXIT_FAILURE; \
        goto fini; \
    } \
} while(0)

void usage(poptContext pc, const char *error);

int set_locale(void);

errno_t sss_signal(int signum);

/* tools_mc_util.c */
errno_t sss_memcache_clear_all(void);

#endif  /* __TOOLS_UTIL_H__ */
