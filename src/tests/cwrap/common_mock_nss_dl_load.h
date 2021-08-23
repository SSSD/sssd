/*
    Authors:
        Iker Pedrosa <ipedrosa@redhat.com>

    Copyright (C) 2021 Red Hat

    SSSD tests: Fake nss dl load

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

#ifndef __COMMON_MOCK_NSS_DL_LOAD_H_
#define __COMMON_MOCK_NSS_DL_LOAD_H_

#include "util/nss_dl_load.h"

errno_t mock_sss_load_nss_pw_symbols(struct sss_nss_ops *ops);

#endif /* __COMMON_MOCK_NSS_DL_LOAD_H_ */
