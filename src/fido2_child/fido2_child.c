/*
    SSSD

    Helper child to commmunicate with FIDO2 devices

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

#include <fido.h>
#include <fido/param.h>

#include "util/debug.h"
#include "util/util.h"

#include "fido2_child.h"

int main(int argc, const char *argv[])
{
    TALLOC_CTX *main_ctx = NULL;
    struct fido2_data data;
    int init_flags = 0;
    errno_t ret = EOK;

    ret = parse_arguments(argc, argv, &data);
    if (ret != EOK) {
        ERROR("Error parsing argument(s).\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "fido2_child started.\n");

    main_ctx = talloc_new(NULL);
    if (main_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed.\n");
        talloc_free(discard_const(debug_prg_name));
        ret = ENOMEM;
        goto done;
    }
    talloc_steal(main_ctx, debug_prg_name);

    ret = check_arguments(&data);
    if (ret != EOK) {
        ERROR("Invalid argument(s).\n");
        goto done;
    }

    init_flags = (int)data.debug_libfido2 | FIDO_DISABLE_U2F_FALLBACK;
    fido_init(init_flags);

    if (data.action == ACTION_REGISTER) {
        ret = register_key(&data);
        if (ret != EOK) {
            ERROR("Error registering key.\n");
            goto done;
        }
    } else if (data.action == ACTION_AUTHENTICATE) {
        ERROR("This action isn't implemented yet.\n");
    }

done:
    talloc_free(main_ctx);

    if (ret != EOK) {
        return EXIT_FAILURE;
    } else {
        return EXIT_SUCCESS;
    }
}
