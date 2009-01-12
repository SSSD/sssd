/*
   SSSD

   Data Provider Backend Storage helper funcitons

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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


#include <errno.h>
#include "ldb.h"
#include "ldb_errors.h"
#include "util/util.h"
#include "providers/dp_backend.h"
#include "nss/nss_ldb.h"
#include <time.h>

/* NOTE: these functions ues ldb sync calls, but the cache db is a
 * local TDB, so there should never be an issue.
 * In case this changes (ex. plugins that contact the network etc..
 * make sure to split functions in multiple async calls */

