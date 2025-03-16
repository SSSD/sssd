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

#ifndef SSS_PRCTL_H_
#define SSS_PRCTL_H_

int sss_prctl_set_dumpable(int dumpable);
int sss_prctl_get_dumpable(void);

int sss_prctl_set_no_new_privs(void);

int sss_prctl_get_keep_caps(void);

int sss_prctl_set_parent_deathsig(long sig);

#endif /* SSS_PRCTL_H_ */
