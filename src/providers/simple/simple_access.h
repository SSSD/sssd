/*
   SSSD

   Simple access control

   Copyright (C) Sumit Bose <sbose@redhat.com> 2010

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

#ifndef __SIMPLE_ACCESS_H__
#define __SIMPLE_ACCESS_H__

#include "util/util.h"

struct simple_ctx {
    struct sss_domain_info *domain;
    struct be_ctx *be_ctx;

    char **allow_users;
    char **deny_users;
    char **allow_groups;
    char **deny_groups;

    time_t last_refresh_of_filter_lists;
};

struct tevent_req *simple_access_check_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct simple_ctx *ctx,
                                            const char *username);

errno_t simple_access_check_recv(struct tevent_req *req,
                                 bool *access_granted);

#endif /* __SIMPLE_ACCESS_H__ */
