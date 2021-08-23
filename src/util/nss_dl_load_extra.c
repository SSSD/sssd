/*
    SSSD

    nss_dl_load_extra.c

    Authors:
        Sumit Bose <sbose@redhat.com>
        Iker Pedrosa <ipedrosa@redhat.com>

    Copyright (C) 2021 Red Hat

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

#include "util/nss_dl_load.h"

errno_t sss_load_nss_pw_symbols(struct sss_nss_ops *ops)
{
    errno_t ret;
    struct sss_nss_symbols syms[] = {
        {(void*)&ops->getpwnam_r, true, "getpwnam_r" },
        {(void*)&ops->getpwuid_r, true, "getpwuid_r" }
    };
    size_t nsyms = sizeof(syms) / sizeof(struct sss_nss_symbols);

    ret = sss_load_nss_symbols(ops, "files", syms, nsyms);

    return ret;
}
