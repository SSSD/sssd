/*
   SSSD

   SSS Client Responder, common header file

   Copyright (C) Red Hat, 2012

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

#ifndef __SSS_RESPONDER_SBUS_H__
#define __SSS_RESPONDER_SBUS_H__

#define NSS_SBUS_SERVICE_NAME "nss"
#define NSS_SBUS_SERVICE_VERSION 0x0001

#define SSS_PAM_SBUS_SERVICE_NAME "pam"
#define SSS_PAM_SBUS_SERVICE_VERSION 0x0001

#define SSS_SUDO_SBUS_SERVICE_NAME "sudo"
#define SSS_SUDO_SBUS_SERVICE_VERSION 0x0001

#define SSS_AUTOFS_SBUS_SERVICE_NAME    "autofs"
#define SSS_AUTOFS_SBUS_SERVICE_VERSION 0x0001

#define SSS_SSH_SBUS_SERVICE_NAME    "ssh"
#define SSS_SSH_SBUS_SERVICE_VERSION 0x0001

#define PAC_SBUS_SERVICE_NAME "pac"
#define PAC_SBUS_SERVICE_VERSION 0x0001

#endif /* __SSS_RESPONDER_SBUS_H__ */
