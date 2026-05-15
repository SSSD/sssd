/*
    Authors:
        Pavel Reichl  <preichl@redhat.com>

    Copyright (C) 2014 Red Hat

    Test for the NSS Responder ID-SID mapping interface

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

#include "util/util.h"
#include "util/sss_ssh.h"
#include "tests/cmocka/common_mock.h"
#include "test_utils.h"

uint8_t key_data_noLF[] = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfymad64oZkWa6q3xLXmCt/LfCRnd6yZSDp7UK6Irx5/Dv69dEKK2kBGL9Wfn+3ZDa6ov2XZrBmUthh8KOJvTw72+axox3kcJ5HwOYZCMeKbcr10RNScGuHErA1HhjTY6M9L8d0atVH2QIxw7ZHoVVnTHC4U4+541YfJkNUiOUIj65cFFZm9ULp32ZPrK+j2wW+XZkHhrZeFMlg4x4fe5FocO6ik1eqLxBejo7tMy+1m3R2a795AIguf6vNWeE5aNMd4pcmPcZHb3JOq3ItzE/3lepXD/3wqMt36EqNykBVE7aJj+LVkcEgjP9CDDsg9j9NB+AuWYmIYqrHW/Rg/vJ developer@sssd.dev.work";

uint8_t key_data_LF[] = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfymad64oZkWa6q3xLXmCt/LfCRnd6yZSDp7UK6Irx5/Dv69dEKK2kBGL9Wfn+3ZDa6ov2XZrBmUthh8KOJvTw72+axox3kcJ5HwOYZCMeKbcr10RNScGuHErA1HhjTY6M9L8d0atVH2QIxw7ZHoVVnTHC4U4+541YfJkNUiOUIj65cFFZm9ULp32ZPrK+j2wW+XZkHhrZeFMlg4x4fe5FocO6ik1eqLxBejo7tMy+1m3R2a795AIguf6vNWeE5aNMd4pcmPcZHb3JOq3ItzE/3lepXD/3wqMt36EqNykBVE7aJj+LVkcEgjP9CDDsg9j9NB+AuWYmIYqrHW/Rg/vJ developer@sssd.dev.work\n";

uint8_t key_data_LFLF[] = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfymad64oZkWa6q3xLXmCt/LfCRnd6yZSDp7UK6Irx5/Dv69dEKK2kBGL9Wfn+3ZDa6ov2XZrBmUthh8KOJvTw72+axox3kcJ5HwOYZCMeKbcr10RNScGuHErA1HhjTY6M9L8d0atVH2QIxw7ZHoVVnTHC4U4+541YfJkNUiOUIj65cFFZm9ULp32ZPrK+j2wW+XZkHhrZeFMlg4x4fe5FocO6ik1eqLxBejo7tMy+1m3R2a795AIguf6vNWeE5aNMd4pcmPcZHb3JOq3ItzE/3lepXD/3wqMt36EqNykBVE7aJj+LVkcEgjP9CDDsg9j9NB+AuWYmIYqrHW/Rg/vJ developer@sssd.dev.work\n\n";

uint8_t key_data_CRLF[] = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfymad64oZkWa6q3xLXmCt/LfCRnd6yZSDp7UK6Irx5/Dv69dEKK2kBGL9Wfn+3ZDa6ov2XZrBmUthh8KOJvTw72+axox3kcJ5HwOYZCMeKbcr10RNScGuHErA1HhjTY6M9L8d0atVH2QIxw7ZHoVVnTHC4U4+541YfJkNUiOUIj65cFFZm9ULp32ZPrK+j2wW+XZkHhrZeFMlg4x4fe5FocO6ik1eqLxBejo7tMy+1m3R2a795AIguf6vNWeE5aNMd4pcmPcZHb3JOq3ItzE/3lepXD/3wqMt36EqNykBVE7aJj+LVkcEgjP9CDDsg9j9NB+AuWYmIYqrHW/Rg/vJ developer@sssd.dev.work\r\n";

uint8_t key_data_CR_somewhere[] = "ssh-rsa AA\rAAB3NzaC1yc2EAAAADAQABAAABAQDfymad64oZkWa6q3xLXmCt/LfCRnd6yZSDp7UK6Irx5/Dv69dEKK2kBGL9Wf+3ZDa6ov2XZrBmUthh8KOJvTw72+axox3kcJ5HwOYZCMeKbcr10RNScGuHErA1HhjTY6M9L8d0atVH2QIxw7ZHoVVnTHC4U4+541YfJkNUiOUIj65cFFZm9ULp32ZPrK+j2wW+XZkHhrZeFMlg4x4fe5FocO6ik1eqLxBejo7tMy+1m3R2a795AIguf6vNWeE5aNMd4pcmPcZHb3JOq3ItzE/3lepXD/3wqMt36EqNykBVE7aJj+LVkcEgjP9CDDsg9j9NB+AuWYmIYqrHW/Rg/vJ developer@sssd.dev.work\n";

void test_textual_public_key(void **state)
{
    TALLOC_CTX *mem_ctx;
    errno_t ret;
    char *res;

    struct sss_ssh_pubkey pkey_null_terminated = {
        .data = key_data_noLF,
        .data_len = sizeof(key_data_noLF)
    };

    struct sss_ssh_pubkey pkey = {
        .data = key_data_noLF,
        .data_len = sizeof(key_data_noLF) - 1 /* ignore trailling '\0' */
    };

    struct sss_ssh_pubkey pkey_LF = {
        .data = key_data_LF,
        .data_len = sizeof(key_data_LF) - 1 /* ignore trailling '\0' */
    };

    struct sss_ssh_pubkey pkey_LFLF = {
        .data = key_data_LFLF,
        .data_len = sizeof(key_data_LFLF) - 1 /* ignore trailling '\0' */
    };

    struct sss_ssh_pubkey pkey_CRLF = {
        .data = key_data_CRLF,
        .data_len = sizeof(key_data_CRLF) - 1 /* ignore trailling '\0' */
    };

    struct sss_ssh_pubkey pkey_CR_somewhere = {
        .data = key_data_CR_somewhere,
        .data_len = sizeof(key_data_CR_somewhere) - 1 /* ignore traill. '\0' */
    };

    mem_ctx = talloc_new(NULL);
    assert_non_null(mem_ctx);
    check_leaks_push(mem_ctx);

    ret = sss_ssh_format_pubkey(mem_ctx, &pkey, &res);
    assert_int_equal(ret, EOK);
    talloc_free(res);

    ret = sss_ssh_format_pubkey(mem_ctx, &pkey_LF, &res);
    assert_int_equal(ret, EOK);
    talloc_free(res);

    ret = sss_ssh_format_pubkey(mem_ctx, &pkey_LFLF, &res);
    assert_int_equal(ret, EINVAL);

    ret = sss_ssh_format_pubkey(mem_ctx, &pkey_null_terminated, &res);
    assert_int_equal(ret, EINVAL);

    ret = sss_ssh_format_pubkey(mem_ctx, &pkey_CRLF, &res);
    assert_int_equal(ret, EINVAL);

    ret = sss_ssh_format_pubkey(mem_ctx, &pkey_CR_somewhere, &res);
    assert_int_equal(ret, EINVAL);

    assert_true(check_leaks_pop(mem_ctx) == true);
    talloc_free(mem_ctx);
}
