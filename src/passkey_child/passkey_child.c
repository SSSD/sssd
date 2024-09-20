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

#include <fido.h>
#include <fido/param.h>

#include "util/debug.h"
#include "util/util.h"

#include "passkey_child.h"

int main(int argc, const char *argv[])
{
    TALLOC_CTX *main_ctx = NULL;
    struct passkey_data data;
    int init_flags = 0;
    errno_t ret = EOK;

    main_ctx = talloc_new(NULL);
    if (main_ctx == NULL) {
        ERROR("talloc_new() failed.\n");
        talloc_free(discard_const(debug_prg_name));
        ret = ENOMEM;
        goto done;
    }

    ret = parse_arguments(main_ctx, argc, argv, &data);
    if (ret != EOK) {
        ERROR("Error parsing argument(s).\n");
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "passkey_child started.\n");
    talloc_steal(main_ctx, debug_prg_name);

    ret = check_arguments(&data);
    if (ret != EOK) {
        ERROR("Invalid argument(s).\n");
        goto done;
    }

    init_flags = (int)data.debug_libfido2 | FIDO_DISABLE_U2F_FALLBACK;
    fido_init(init_flags);

    if (data.action == ACTION_REGISTER) {
        ret = register_key(&data, TIMEOUT);
        if (ret != EOK) {
            ERROR("Error registering key.\n");
            goto done;
        }
    } else if (data.action == ACTION_AUTHENTICATE) {
        ret = authenticate(&data, TIMEOUT);
        if (ret == EOK) {
            PRINT("Authentication success.\n");
            goto done;
        } else {
            ERROR("Authentication error.\n");
            goto done;
        }
    } else if (data.action == ACTION_GET_ASSERT) {
        ret = get_assert_data(&data, TIMEOUT);
        if (ret != EOK) {
            ERROR("Error getting assertion data.\n");
            goto done;
        }
    } else if (data.action == ACTION_VERIFY_ASSERT) {
        ret = verify_assert_data(&data);
        if (ret == EOK) {
            PRINT("Verification success.\n");
            goto done;
        } else {
            ERROR("Verification error.\n");
            goto done;
        }
    }

done:
    talloc_free(main_ctx);

    if (ret != EOK) {
        return EXIT_FAILURE;
    } else {
        return EXIT_SUCCESS;
    }
}
