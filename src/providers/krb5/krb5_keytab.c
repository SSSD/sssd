/*
    SSSD

    Kerberos 5 Backend Module -- keytab related utilities

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2014 Red Hat

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
#include "util/sss_krb5.h"

krb5_error_code copy_keytab_into_memory(TALLOC_CTX *mem_ctx, krb5_context kctx,
                                        char *inp_keytab_file,
                                        char **_mem_name,
                                        krb5_keytab *_mem_keytab)
{
    krb5_error_code kerr;
    krb5_error_code kt_err;
    krb5_keytab keytab = NULL;
    krb5_keytab mem_keytab = NULL;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;
    char keytab_name[MAX_KEYTAB_NAME_LEN];
    char *sep;
    char *mem_name = NULL;
    char *keytab_file;
    char default_keytab_name[MAX_KEYTAB_NAME_LEN];

    keytab_file = inp_keytab_file;
    if (keytab_file == NULL) {
        kerr = krb5_kt_default_name(kctx, default_keytab_name,
                                    sizeof(default_keytab_name));
        if (kerr != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "krb5_kt_default_name failed.\n");
            return kerr;
        }

        keytab_file = default_keytab_name;
    }

    kerr = krb5_kt_resolve(kctx, keytab_file, &keytab);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "error resolving keytab [%s].\n",
                                    keytab_file);
        return kerr;
    }

    kerr = krb5_kt_have_content(kctx, keytab);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "keytab [%s] has not entries.\n",
                                    keytab_file);
        goto done;
    }

    kerr = krb5_kt_get_name(kctx, keytab, keytab_name, sizeof(keytab_name));
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to read name for keytab [%s].\n",
                                    keytab_file);
        goto done;
    }

    sep = strchr(keytab_name, ':');
    if (sep == NULL || sep[1] == '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Keytab name [%s] does not have delimiter[:] .\n", keytab_name);
        kerr = KRB5KRB_ERR_GENERIC;
        goto done;
    }

    if (strncmp(keytab_name, "MEMORY:", sizeof("MEMORY:") -1) == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "Keytab [%s] is already memory keytab.\n",
                                 keytab_name);
        *_mem_name = talloc_strdup(mem_ctx, keytab_name);
        if(*_mem_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            kerr = KRB5KRB_ERR_GENERIC;
            goto done;
        }
        kerr = 0;
        goto done;
    }

    mem_name = talloc_asprintf(mem_ctx, "MEMORY:%s", sep + 1);
    if (mem_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        kerr = KRB5KRB_ERR_GENERIC;
        goto done;
    }

    kerr = krb5_kt_resolve(kctx, mem_name, &mem_keytab);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "error resolving keytab [%s].\n",
                                    mem_name);
        goto done;
    }

    memset(&cursor, 0, sizeof(cursor));
    kerr = krb5_kt_start_seq_get(kctx, keytab, &cursor);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "error reading keytab [%s].\n", keytab_file);
        goto done;
    }

    memset(&entry, 0, sizeof(entry));
    while ((kt_err = krb5_kt_next_entry(kctx, keytab, &entry, &cursor)) == 0) {
        kerr = krb5_kt_add_entry(kctx, mem_keytab, &entry);
        if (kerr != 0) {
            DEBUG(SSSDBG_OP_FAILURE, "krb5_kt_add_entry failed.\n");
            goto done;
        }

        kerr = sss_krb5_free_keytab_entry_contents(kctx, &entry);
        if (kerr != 0) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Failed to free keytab entry.\n");
        }
        memset(&entry, 0, sizeof(entry));
    }

    kerr = krb5_kt_end_seq_get(kctx, keytab, &cursor);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_kt_end_seq_get failed.\n");
        goto done;
    }

    /* check if we got any errors from krb5_kt_next_entry */
    if (kt_err != 0 && kt_err != KRB5_KT_END) {
        DEBUG(SSSDBG_CRIT_FAILURE, "error reading keytab [%s].\n", keytab_file);
        kerr = KRB5KRB_ERR_GENERIC;
        goto done;
    }

    *_mem_name = mem_name;
    if (_mem_keytab != NULL) {
        *_mem_keytab = mem_keytab;
    }

    kerr = 0;
done:

    if (kerr != 0) {
        talloc_free(mem_name);
    }

    if (keytab != NULL && krb5_kt_close(kctx, keytab) != 0) {
            DEBUG(SSSDBG_MINOR_FAILURE, "krb5_kt_close failed");
    }

    return kerr;
}
