/*
    SSSD

    Copyright (C) 2025 Gleb Popov <arrowd@FreeBSD.org>

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
#include "util/sss_prctl.h"

#ifdef HAVE_PRCTL
#include <sys/prctl.h>

int sss_prctl_set_dumpable(int dumpable)
{
    return prctl(PR_SET_DUMPABLE, dumpable);
}

int sss_prctl_get_dumpable(void)
{
    return prctl(PR_GET_DUMPABLE);
}

int sss_prctl_set_no_new_privs(void)
{
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
}

int sss_prctl_get_keep_caps(void)
{
    return prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0);
}

int sss_prctl_set_parent_deathsig(long sig)
{
    return prctl(PR_SET_PDEATHSIG, sig, 0, 0, 0);
}

#elif defined(HAVE_PROCCTL)
#include <sys/procctl.h>

int sss_prctl_set_dumpable(int dumpable)
{
    dumpable = dumpable ? PROC_TRACE_CTL_ENABLE : PROC_TRACE_CTL_DISABLE;
    return procctl(P_PID, 0, PROC_TRACE_CTL, &dumpable);
}

int sss_prctl_get_dumpable(void)
{
    int ret, dumpable = 0;
    ret = procctl(P_PID, 0, PROC_TRACE_STATUS, &dumpable);
    if (ret == -1)
        return 0;
    return dumpable != -1; // -1 means "not dumpable"
}

int sss_prctl_set_no_new_privs(void)
{
    int enable = PROC_NO_NEW_PRIVS_ENABLE;
    return procctl(P_PID, 0, PROC_NO_NEW_PRIVS_CTL, &enable);
}

int sss_prctl_get_keep_caps(void)
{
    return 0;
}

int sss_prctl_set_parent_deathsig(long sig)
{
    return procctl(P_PID, 0, PROC_PDEATHSIG_CTL, &sig);
}

#endif
