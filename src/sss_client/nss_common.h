/*
   SSSD

   Common routines for classical and enhanced NSS interface

   Authors:
        Sumit Bose <sbose@redhat.com>

   Copyright (C) Red Hat, Inc 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/



struct sss_nss_pw_rep {
    struct passwd *result;
    char *buffer;
    size_t buflen;
};

int sss_nss_getpw_readrep(struct sss_nss_pw_rep *pr,
                          uint8_t *buf, size_t *len);

struct sss_nss_gr_rep {
    struct group *result;
    char *buffer;
    size_t buflen;
};

int sss_nss_getgr_readrep(struct sss_nss_gr_rep *pr,
                          uint8_t *buf, size_t *len);
