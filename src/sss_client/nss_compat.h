/*
    SSSD

    nss_compat.h

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2010 Red Hat

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

    Portions of this source file were copied from nss-pam-ldapd version
    0.7.8, licensed under LGPLv2.1+
*/

#ifndef NSS_COMPAT_H_
#define NSS_COMPAT_H_

/* We also define struct __netgrent because it's definition is
   not publically available. This is taken from inet/netgroup.h
   of the glibc (2.3.6) source tarball.
   The first part of the struct is the only part that is modified
   by our getnetgrent() function, all the other fields are not
   touched at all. */
struct __netgrent
{
  enum { triple_val, group_val } type;
  union
  {
    struct
    {
      const char *host;
      const char *user;
      const char *domain;
    } triple;
    const char *group;
  } val;
  /* the following stuff is used by some NSS services
     but not by ours (it's not completely clear how these
     are shared between different services) or is used
     by our caller */
  char *data;
  size_t data_size;
  union
  {
    char *cursor;
    unsigned long int position;
  } idx;  /* added name to union to avoid warning */
  int first;
  struct name_list *known_groups;
  struct name_list *needed_groups;
  void *nip; /* changed from `service_user *nip' */
};

#endif /* NSS_COMPAT_H_ */
