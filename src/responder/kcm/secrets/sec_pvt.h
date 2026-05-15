/*
   SSSD

   Local secrets database - private header

   Copyright (C) Red Hat 2018

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

#ifndef __SECRETS_PVT_H_
#define __SECRETS_PVT_H_

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

#include "secrets.h"

struct sss_sec_ctx {
    struct ldb_context *ldb;

    struct sss_sec_quota *quota_kcm;
};

struct sss_sec_req {
    char *path;
    const char *basedn;
    struct ldb_dn *req_dn;
    struct sss_sec_quota *quota;

    struct sss_sec_ctx *sctx;
};

#endif /* __SECRETS_PVT_H_ */
