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

#include <stdlib.h>

#include "util/util.h"

struct simple_ctx {
    char **allow_users;
    char **deny_users;
};

errno_t simple_access_check(struct simple_ctx *ctx, const char *username,
                            bool *access_granted);
#endif /* __SIMPLE_ACCESS_H__ */
