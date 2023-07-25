/*
    Authors:
        Jan Cholasta <jcholast@redhat.com>

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

#ifndef _SSS_SSH_H_
#define _SSS_SSH_H_

#define SSS_SSH_REQ_ALIAS   0x01
#define SSS_SSH_REQ_DOMAIN  0x02
#define SSS_SSH_REQ_MASK    0x03

struct sss_ssh_pubkey {
    uint8_t *data;
    size_t data_len;
};

struct sss_ssh_ent {
    char *name;

    struct sss_ssh_pubkey *pubkeys;
    size_t num_pubkeys;

    char **aliases;
    size_t num_aliases;
};

errno_t
sss_ssh_make_ent(TALLOC_CTX *mem_ctx,
                 struct ldb_message *msg,
                 struct sss_ssh_ent **result);

errno_t
sss_ssh_format_pubkey(TALLOC_CTX *mem_ctx,
                      struct sss_ssh_pubkey *pubkey,
                      char **result);

errno_t
sss_ssh_print_pubkey(struct sss_ssh_pubkey *pubkey);

#endif /* _SSS_SSH_H_ */
