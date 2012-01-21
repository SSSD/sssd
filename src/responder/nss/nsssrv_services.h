/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2012 Red Hat

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

#ifndef NSSSRV_SERVICES_H_
#define NSSSRV_SERVICES_H_

int nss_cmd_getservbyname(struct cli_ctx *cctx);
int nss_cmd_getservbyport(struct cli_ctx *cctx);

int nss_cmd_setservent(struct cli_ctx *cctx);
int nss_cmd_getservent(struct cli_ctx *cctx);
int nss_cmd_endservent(struct cli_ctx *cctx);

#endif /* NSSSRV_SERVICES_H_ */
