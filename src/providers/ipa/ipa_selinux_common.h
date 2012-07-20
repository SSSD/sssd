/*
    SSSD

    IPA Backend Module -- SELinux common routines

    Authors:
        Jan Zeleny <jzeleny@redhat.com>

    Copyright (C) 2012 Red Hat

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

#ifndef IPA_SELINUX_COMMON_H_
#define IPA_SELINUX_COMMON_H_

errno_t ipa_save_host(struct sysdb_ctx *sysdb,
                      struct sysdb_attrs *host);

errno_t ipa_save_user_maps(struct sysdb_ctx *sysdb,
                           size_t map_count,
                           struct sysdb_attrs **maps);

#endif /* IPA_SELINUX_COMMON_H_ */
