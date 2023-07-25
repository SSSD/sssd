/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2018 Red Hat

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

#ifndef _SSS_IFACE_H_
#define _SSS_IFACE_H_

#include "config.h"

#include <stdint.h>
#include <talloc.h>

#include "confdb/confdb.h"
#include "providers/data_provider_req.h"
#include "providers/data_provider/dp_flags.h"

#define SSS_MONITOR_ADDRESS "unix:path=" PIPE_PATH "/private/sbus-monitor"
#define SSS_BACKEND_ADDRESS "unix:path=" PIPE_PATH "/private/sbus-dp_%s"

#define SSS_BUS_MONITOR     "sssd.monitor"
#define SSS_BUS_AUTOFS      "sssd.autofs"
#define SSS_BUS_IFP         "sssd.ifp"
#define SSS_BUS_NSS         "sssd.nss"
#define SSS_BUS_PAC         "sssd.pac"
#define SSS_BUS_PAM         "sssd.pam"
#define SSS_BUS_SSH         "sssd.ssh"
#define SSS_BUS_SUDO        "sssd.sudo"

#define SSS_BUS_PATH        "/sssd"

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
#define SSS_IFP_SBUS_SERVICE_NAME    "ifp"
#define SSS_IFP_SBUS_SERVICE_VERSION 0x0001
#define PAC_SBUS_SERVICE_NAME "pac"
#define PAC_SBUS_SERVICE_VERSION 0x0001

/**
 * Return domain address.
 */
char *
sss_iface_domain_address(TALLOC_CTX *mem_ctx,
                         struct sss_domain_info *domain);

/**
 * Return domain bus name.
 */
char *
sss_iface_domain_bus(TALLOC_CTX *mem_ctx,
                     struct sss_domain_info *domain);

/**
 * Return proxy child bus name.
 */
char *
sss_iface_proxy_bus(TALLOC_CTX *mem_ctx,
                    uint32_t id);

#endif /* _SSS_IFACE_H_ */
