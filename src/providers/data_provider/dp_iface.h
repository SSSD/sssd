/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#ifndef DP_IFACE_H_
#define DP_IFACE_H_

#include "sbus/sssd_dbus.h"
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp_responder_iface.h"
#include "providers/data_provider/dp.h"

#define DP_PATH "/org/freedesktop/sssd/dataprovider"

errno_t dp_register_sbus_interface(struct sbus_connection *conn,
                                   struct dp_client *pvt);

errno_t dp_get_account_info_handler(struct sbus_request *sbus_req,
                                    void *dp_cli,
                                    uint32_t dp_flags,
                                    uint32_t entry_type,
                                    uint32_t attr_type,
                                    const char *filter,
                                    const char *domain,
                                    const char *extra);

errno_t dp_pam_handler(struct sbus_request *sbus_req, void *dp_cli);

errno_t dp_sudo_handler(struct sbus_request *sbus_req, void *dp_cli);

errno_t dp_host_handler(struct sbus_request *sbus_req,
                        void *dp_cli,
                        uint32_t dp_flags,
                        const char *name,
                        const char *alias);

errno_t dp_autofs_handler(struct sbus_request *sbus_req,
                          void *dp_cli,
                          uint32_t dp_flags,
                          const char *mapname);

errno_t dp_subdomains_handler(struct sbus_request *sbus_req,
                              void *dp_cli,
                              const char *domain_hint);

/* org.freedesktop.sssd.DataProvider.Backend */
errno_t dp_backend_is_online(struct sbus_request *sbus_req,
                             void *dp_cli,
                             const char *domain);

/* org.freedesktop.sssd.DataProvider.Failover */
errno_t dp_failover_list_services(struct sbus_request *sbus_req,
                                  void *dp_cli,
                                  const char *domname);

#endif /* DP_IFACE_H_ */
