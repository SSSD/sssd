/*
    SSSD

    NSS Responder ID-mapping interface - private calls

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2017 Red Hat

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

#ifndef SSS_NSS_IDMAP_PRIVATE_H_
#define SSS_NSS_IDMAP_PRIVATE_H_

int sss_nss_timedlock(unsigned int timeout_ms, int *time_left_ms);

#endif /* SSS_NSS_IDMAP_PRIVATE_H_ */
