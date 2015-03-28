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
#include "providers/krb5/krb5_common.h"

static krb5_error_code do_keytab_copy(krb5_context kctx, krb5_keytab s_keytab,
                                      krb5_keytab d_keytab)
{
    krb5_error_code kerr;
    krb5_error_code kt_err;
    krb5_kt_cursor cursor;
    krb5_keytab_entry entry;

    memset(&cursor, 0, sizeof(cursor));
    kerr = krb5_kt_start_seq_get(kctx, s_keytab, &cursor);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "error reading keytab.\n");
        return kerr;
    }

    memset(&entry, 0, sizeof(entry));
    while ((kt_err = krb5_kt_next_entry(kctx, s_keytab, &entry,
                                        &cursor)) == 0) {
        kerr = krb5_kt_add_entry(kctx, d_keytab, &entry);
        if (kerr != 0) {
            DEBUG(SSSDBG_OP_FAILURE, "krb5_kt_add_entry failed.\n");
            kt_err = krb5_kt_end_seq_get(kctx, s_keytab, &cursor);
            if (kt_err != 0) {
                DEBUG(SSSDBG_TRACE_ALL,
                      "krb5_kt_end_seq_get failed with [%d], ignored.\n",
                      kt_err);
            }
            return kerr;
        }

        kerr = sss_krb5_free_keytab_entry_contents(kctx, &entry);
        if (kerr != 0) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Failed to free keytab entry.\n");
            kt_err = krb5_kt_end_seq_get(kctx, s_keytab, &cursor);
            if (kt_err != 0) {
                DEBUG(SSSDBG_TRACE_ALL,
                      "krb5_kt_end_seq_get failed with [%d], ignored.\n",
                      kt_err);
            }
            return kerr;
        }
        memset(&entry, 0, sizeof(entry));
    }

    kerr = krb5_kt_end_seq_get(kctx, s_keytab, &cursor);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "krb5_kt_end_seq_get failed.\n");
        return kerr;
    }

    /* check if we got any errors from krb5_kt_next_entry */
    if (kt_err != 0 && kt_err != KRB5_KT_END) {
        DEBUG(SSSDBG_CRIT_FAILURE, "error reading keytab.\n");
        return kt_err;
    }

    return 0;
}

krb5_error_code copy_keytab_into_memory(TALLOC_CTX *mem_ctx, krb5_context kctx,
                                        const char *inp_keytab_file,
                                        char **_mem_name,
                                        krb5_keytab *_mem_keytab)
{
    krb5_error_code kerr;
    krb5_keytab keytab = NULL;
    krb5_keytab mem_keytab = NULL;
    krb5_keytab tmp_mem_keytab = NULL;
    char keytab_name[MAX_KEYTAB_NAME_LEN];
    char *sep;
    char *mem_name = NULL;
    char *tmp_mem_name = NULL;
    const char *keytab_file;
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

    kerr = sss_krb5_kt_have_content(kctx, keytab);
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

    tmp_mem_name = talloc_asprintf(mem_ctx, "MEMORY:%s.tmp", sep + 1);
    if (tmp_mem_name == NULL) {
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

    kerr = krb5_kt_resolve(kctx, tmp_mem_name, &tmp_mem_keytab);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "error resolving keytab [%s].\n",
                                    tmp_mem_name);
        goto done;
    }

    kerr = do_keytab_copy(kctx, keytab, tmp_mem_keytab);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to copy keytab [%s] into [%s].\n",
                                    keytab_file, tmp_mem_name);
        goto done;
    }

    /* krb5_kt_add_entry() adds new entries into MEMORY keytabs at the
     * beginning and not at the end as for FILE keytabs. Since we want to keep
     * the processing order we have to copy the MEMORY keytab again to retain
     * the order from the FILE keytab. */

    kerr = do_keytab_copy(kctx, tmp_mem_keytab, mem_keytab);
    if (kerr != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to copy keytab [%s] into [%s].\n",
                                    tmp_mem_name, mem_name);
        goto done;
    }

    *_mem_name = mem_name;
    if (_mem_keytab != NULL) {
        *_mem_keytab = mem_keytab;
    }

    kerr = 0;
done:

    talloc_free(tmp_mem_name);

    if (kerr != 0) {
        talloc_free(mem_name);
    }

    if (tmp_mem_keytab != NULL && krb5_kt_close(kctx, tmp_mem_keytab) != 0) {
        DEBUG(SSSDBG_MINOR_FAILURE, "krb5_kt_close failed.\n");
    }

    if (keytab != NULL && krb5_kt_close(kctx, keytab) != 0) {
        DEBUG(SSSDBG_MINOR_FAILURE, "krb5_kt_close failed.\n");
    }

    return kerr;
}
