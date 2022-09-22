/*
    SSSD

    Helper child to commmunicate with passkey devices

    Authors:
        Iker Pedrosa <ipedrosa@redhat.com>

    Copyright (C) 2022 Red Hat

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

#include "util/debug.h"
#include "util/util.h"

#include "passkey_child.h"

errno_t
list_devices(fido_dev_info_t *dev_list, size_t *dev_number)
{
    errno_t ret;

    for (int i = 0; i < TIMEOUT; i += FREQUENCY) {
        ret = fido_dev_info_manifest(dev_list, DEVLIST_SIZE, dev_number);
        if (ret != FIDO_OK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Unable to discover device(s) [%d]: %s.\n",
                  ret, fido_strerr(ret));
        }

        if ((*dev_number) != 0) {
            DEBUG(SSSDBG_TRACE_FUNC, "Device found.\n");
            break;
        }

        if (i < (TIMEOUT - 1)) {
            DEBUG(SSSDBG_TRACE_FUNC, "No device available, retrying.\n");
            sleep(FREQUENCY);
        }
    }

    return ret;
}

errno_t
select_device(fido_dev_info_t *dev_list, size_t dev_index, fido_dev_t *dev)
{
    const char *path;
    const fido_dev_info_t *di = NULL;
    errno_t ret;

    di = fido_dev_info_ptr(dev_list, dev_index);
    if (di == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_dev_info_ptr failed.\n");
        ret = ENOMEM;
        goto done;
    }

    path = fido_dev_info_path(di);
    if (path == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_dev_info_path failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = fido_dev_open(dev, path);
    if (ret != FIDO_OK) {
        DEBUG(SSSDBG_OP_FAILURE, "fido_dev_open failed [%d]: %s.\n",
              ret, fido_strerr(ret));
    }

done:
    return ret;
}
