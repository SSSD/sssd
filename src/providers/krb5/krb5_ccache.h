/*
    SSSD

    Kerberos 5 Backend Module -- ccache related utilities

    Authors:
        Sumit Bose <sbose@redhat.com>
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2014 Red Hat

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

#ifndef __KRB5_CCACHE_H__
#define __KRB5_CCACHE_H__

#include "util/util.h"

struct tgt_times {
    time_t authtime;
    time_t starttime;
    time_t endtime;
    time_t renew_till;
};

errno_t create_ccache_dir(const char *ccdirname,
                          pcre *illegal_re,
                          uid_t uid, gid_t gid);

errno_t sss_krb5_precreate_ccache(const char *ccname, pcre *illegal_re,
                                  uid_t uid, gid_t gid);

errno_t sss_krb5_cc_destroy(const char *ccname, uid_t uid, gid_t gid);

errno_t sss_krb5_check_ccache_princ(uid_t uid, gid_t gid,
                                    const char *ccname, const char *principal);

errno_t sss_krb5_cc_verify_ccache(const char *ccname, uid_t uid, gid_t gid,
                                  const char *realm, const char *principal);

errno_t get_ccache_file_data(const char *ccache_file, const char *client_name,
                             struct tgt_times *tgtt);

errno_t safe_remove_old_ccache_file(const char *old_ccache,
                                    const char *new_ccache,
                                    uid_t uid, gid_t gid);

#endif /* __KRB5_CCACHE_H__ */
