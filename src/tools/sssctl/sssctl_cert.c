/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Certificate related utilities

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

#include <popt.h>
#include <stdio.h>
#include <talloc.h>

#include "util/util.h"
#include "tools/common/sss_tools.h"
#include "tools/sssctl/sssctl.h"
#include "lib/certmap/sss_certmap.h"
#include "util/crypto/sss_crypto.h"
#include "responder/ifp/ifp_iface/ifp_iface_sync.h"
#ifdef HAVE_NSS
#include "util/crypto/nss/nss_util.h"
#endif

#define PEM_HEAD "-----BEGIN CERTIFICATE-----\n"
#define PEM_FOOT "-----END CERTIFICATE-----"

errno_t sssctl_cert_show(struct sss_cmdline *cmdline,
                         struct sss_tool_ctx *tool_ctx,
                         void *pvt)
{
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;
    int verbose = 0;
    const char *cert_b64 = NULL;
    char *desc;
    uint8_t *der_cert = NULL;
    size_t der_size;

    /* Parse command line. */
    struct poptOption options[] = {
        {"verbose", 'v', POPT_ARG_NONE, &verbose, 0, _("Show debug information"), NULL },
        POPT_TABLEEND
    };

    ret = sss_tool_popt_ex(cmdline, options, SSS_TOOL_OPT_OPTIONAL,
                           NULL, NULL, "CERTIFICATE-BASE64-ENCODED",
                           _("Specify base64 encoded certificate."),
                           &cert_b64, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    der_cert = sss_base64_decode(tmp_ctx, cert_b64, &der_size);
    if (der_cert == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to decode base64 string.\n");
        ret = EINVAL;
        goto done;
    }

    ret = sss_certmap_display_cert_content(tmp_ctx, der_cert, der_size, &desc);
    if (ret != 0) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to parsed certificate.\n");
        goto done;
    }

    printf("%s\n", desc);
    ret = EOK;

done:
    talloc_free(tmp_ctx);

#ifdef HAVE_NSS
    /* Cleanup NSS and NSPR to make Valgrind happy. */
    nspr_nss_cleanup();
#endif

    return ret;
}

errno_t sssctl_cert_map(struct sss_cmdline *cmdline,
                        struct sss_tool_ctx *tool_ctx,
                        void *pvt)
{
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;
    int verbose = 0;
    const char *cert_b64 = NULL;
    char *cert_pem = NULL;
    struct sbus_sync_connection *conn;
    const char **paths;
    size_t c;
    const char *name;

    /* Parse command line. */
    struct poptOption options[] = {
        {"verbose", 'v', POPT_ARG_NONE, &verbose, 0, _("Show debug information"), NULL },
        POPT_TABLEEND
    };

    ret = sss_tool_popt_ex(cmdline, options, SSS_TOOL_OPT_OPTIONAL,
                           NULL, NULL, "CERTIFICATE-BASE64-ENCODED",
                           _("Specify base64 encoded certificate."),
                           &cert_b64, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse command arguments\n");
        return ret;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        return ENOMEM;
    }

    cert_pem = talloc_asprintf(tmp_ctx, "%s%s\n%s",
                                        PEM_HEAD, cert_b64, PEM_FOOT);
    if (cert_pem == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!\n");
        ret = ENOMEM;
        goto done;
    }

    conn = sbus_sync_connect_system(tmp_ctx, NULL);
    if (conn == NULL) {
        fprintf(stderr, _("Unable to connect to system bus!\n"));
        ret = EIO;
        goto done;
    }

    ret = sbus_call_ifp_users_ListByCertificate(tmp_ctx, conn, IFP_BUS,
                                                IFP_PATH_USERS, cert_pem, -1,
                                                &paths);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to map certificate [%d]: %s\n",
              ret, sss_strerror(ret));
        PRINT_IFP_WARNING(ret);
        goto done;
    }

    if (paths != NULL) {
        for (c = 0; paths[c] != NULL; c++) {
            ret = sbus_get_ifp_user_name(tmp_ctx, conn, IFP_BUS, paths[c],
                                         &name);
            if (ret != EOK) {
                goto done;
            }

            puts(name);
        }
    } else {
        puts(" - no mapped users found -");
    }

    ret = EOK;
done:

#ifdef HAVE_NSS
    /* Cleanup NSS and NSPR to make Valgrind happy. */
    nspr_nss_cleanup();
#endif

    talloc_free(tmp_ctx);

    return ret;
}
