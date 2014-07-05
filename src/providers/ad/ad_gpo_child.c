/*
    SSSD

    AD GPO Backend Module -- perform SMB and CSE processing in a child process

    Authors:
        Yassir Elley <yelley@redhat.com>

    Copyright (C) 2013 Red Hat

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

#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <popt.h>
#include <libsmbclient.h>
#include <security/pam_modules.h>

#include "util/util.h"
#include "util/child_common.h"
#include "providers/dp_backend.h"
#include "sss_cli.h"

#define RIGHTS_SECTION "Privilege Rights"
#define ALLOW_LOGON_LOCALLY "SeInteractiveLogonRight"
#define DENY_LOGON_LOCALLY "SeDenyInteractiveLogonRight"
#define SMB_BUFFER_SIZE 65536

struct input_buffer {
    const char *smb_uri;
    const char *unix_path;
};

static errno_t
unpack_buffer(uint8_t *buf,
              size_t size,
              struct input_buffer *ibuf)
{
    size_t p = 0;
    uint32_t len;

    /* smb_uri size and length */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);

    DEBUG(SSSDBG_TRACE_ALL, "smb_uri size: %d\n", len);

    if (len == 0) {
        return EINVAL;
    } else {
        if ((p + len ) > size) return EINVAL;
        ibuf->smb_uri = talloc_strndup(ibuf, (char *)(buf + p), len);
        if (ibuf->smb_uri == NULL) return ENOMEM;
        DEBUG(SSSDBG_TRACE_ALL, "got smb_uri: %s\n", ibuf->smb_uri);
        p += len;
    }

    /* unix_path size and length */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);

    DEBUG(SSSDBG_TRACE_ALL, "unix_path size: %d\n", len);

    if (len == 0) {
        return EINVAL;
    } else {
        if ((p + len ) > size) return EINVAL;
        ibuf->unix_path = talloc_strndup(ibuf, (char *)(buf + p), len);
        if (ibuf->unix_path == NULL) return ENOMEM;
        DEBUG(SSSDBG_TRACE_ALL, "got unix_path: %s\n", ibuf->unix_path);
        p += len;
    }

    return EOK;
}


static errno_t
pack_buffer(struct response *r,
            int result)
{
    size_t p = 0;

    /* A buffer with the following structure must be created:
     *   uint32_t status of the request (required)
     */
    r->size = sizeof(uint32_t);

    r->buf = talloc_array(r, uint8_t, r->size);
    if(r->buf == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "result [%d]\n", result);

    /* result */
    SAFEALIGN_SET_UINT32(&r->buf[p], result, &p);

    return EOK;
}

static errno_t
prepare_response(TALLOC_CTX *mem_ctx,
                 int result,
                 struct response **rsp)
{
    int ret;
    struct response *r = NULL;

    r = talloc_zero(mem_ctx, struct response);
    if (r == NULL) {
        return ENOMEM;
    }

    r->buf = NULL;
    r->size = 0;

    ret = pack_buffer(r, result);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pack_buffer failed\n");
        return ret;
    }

    *rsp = r;
    DEBUG(SSSDBG_TRACE_FUNC, "r->size: %zu\n", r->size);
    return EOK;
}

static void
sssd_krb_get_auth_data_fn(const char * pServer,
                          const char * pShare,
                          char * pWorkgroup,
                          int maxLenWorkgroup,
                          char * pUsername,
                          int maxLenUsername,
                          char * pPassword,
                          int maxLenPassword)
{
    /* since we are using kerberos for authentication, we simply return */
    return;
}

/*
 * This function prepares the gpo_cache by:
 * - parsing the input_unix_path into its component directories
 * - creating each component directory (if it doesn't already exist)
 */
static errno_t prepare_gpo_cache(TALLOC_CTX *mem_ctx,
                                 const char *cache_dir,
                                 const char *input_unix_path)
{
    char *current_dir;
    char *ptr;
    const char delim = '/';
    int num_dirs = 0;
    int i;
    char *first = NULL;
    char *last = NULL;
    char *unix_path = NULL;

    unix_path = talloc_strdup(mem_ctx, input_unix_path);
    if (unix_path == NULL) {
        return ENOMEM;
    }

    current_dir = talloc_strdup(mem_ctx, cache_dir);
    if (current_dir == NULL) {
        return ENOMEM;
    }

    ptr = unix_path + 1;
    while ((ptr = strchr(ptr, delim))) {
        ptr++;
        num_dirs++;
    }

    ptr = unix_path + 1;

    for (i = 0; i < num_dirs; i++) {
        first = ptr;
        last = strchr(first, delim);
        if (last == NULL) {
            return EINVAL;
        }
        *last = '\0';
        last++;

        current_dir = talloc_asprintf(mem_ctx, "%s/%s", current_dir, first);
        if ((mkdir(current_dir, 0644)) < 0 && errno != EEXIST) {
            return EINVAL;
        }

        ptr = last;
    }

    return EOK;

}

/*
 * This function stores the input buf to a local file, whose file path
 * is constructed by concatenating GPO_CACHE_PATH to the input unix_path.
 * Note that the backend will later read the policy file from the same file path.
 */
static errno_t store_bytes_in_gpo_cache(const char *unix_path,
                                        uint8_t *buf,
                                        int buflen)
{
    int ret;
    int fd = -1;
    char *tmp_name = NULL;
    ssize_t written;
    mode_t old_umask;
    char *filename = NULL;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* create component directories of unix_path, if needed */
    ret = prepare_gpo_cache(tmp_ctx, GPO_CACHE_PATH, unix_path);

    filename = talloc_asprintf(tmp_ctx, GPO_CACHE_PATH"%s", unix_path);
    tmp_name = talloc_asprintf(tmp_ctx, "%sXXXXXX", filename);
    if (tmp_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    old_umask = umask(077);
    fd = mkstemp(tmp_name);
    umask(old_umask);
    if (fd == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "mkstemp failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    errno = 0;
    written = sss_atomic_write_s(fd, buf, buflen);
    if (written == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "write failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    if (written != buflen) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Write error, wrote [%zd] bytes, expected [%d]\n",
               written, buflen);
        ret = EIO;
        goto done;
    }

    ret = fchmod(fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "fchmod failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    ret = close(fd);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "close failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    ret = rename(tmp_name, filename);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "rename failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

 done:

    if (ret != EOK) {
      DEBUG(SSSDBG_CRIT_FAILURE, "Error encountered: %d.\n", ret);
    }

    talloc_free(tmp_ctx);
    return ret;
}

/*
 * This cse-specific function (GP_EXT_GUID_SECURITY) opens an SMB connection,
 * retrieves the data referenced by the input smb_uri, and then closes the SMB
 * connection. The data is then written to a file in the GPO_CACHE directory,
 * to be read by the backend.
 */
static errno_t
process_security_settings_cse(TALLOC_CTX *mem_ctx,
                              const char *smb_uri,
                              const char *unix_path)
{
    SMBCCTX *context;
    int ret = 0;
    uint8_t *buf = NULL;
    int buflen = 0;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_ALL, "%s\n", smb_uri);
    DEBUG(SSSDBG_TRACE_ALL, "%s\n", unix_path);

    context = smbc_new_context();
    if (context == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not allocate new smbc context\n");
        ret = ENOMEM;
        goto done;
    }

    smbc_setFunctionAuthData(context, sssd_krb_get_auth_data_fn);
    smbc_setOptionUseKerberos(context, 1);

    /* Initialize the context using the previously specified options */
    if (smbc_init_context(context) == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not initialize smbc context\n");
        ret = ENOMEM;
        goto done;
    }

    /* Tell the compatibility layer to use this context */
    smbc_set_context(context);

    int remotehandle = smbc_open(smb_uri, O_RDONLY, 0755);
    if (remotehandle < 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "smbc_open failed\n");
        ret = EPIPE;
        goto done;
    }

    buf = talloc_array(tmp_ctx, uint8_t, SMB_BUFFER_SIZE);
    buflen = smbc_read(remotehandle, buf, SMB_BUFFER_SIZE);
    if(buflen < 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "smbc_read failed\n");
        ret = EPIPE;
        goto done;
    }

    DEBUG(SSSDBG_CRIT_FAILURE, "buflen: %d\n", buflen);

    smbc_close(remotehandle);

    ret = store_bytes_in_gpo_cache(unix_path, buf, buflen);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "store_bytes_in_gpo_cache failed [%d][%s]\n",
              ret, strerror(ret));
        goto done;
    }

 done:
    smbc_free_context(context, 0);
    talloc_free(tmp_ctx);
    return ret;
}

int
main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int debug_fd = -1;
    errno_t ret;
    int result;
    TALLOC_CTX *main_ctx = NULL;
    uint8_t *buf = NULL;
    ssize_t len = 0;
    struct input_buffer *ibuf = NULL;
    struct response *resp = NULL;
    size_t written;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        {"debug-level", 'd', POPT_ARG_INT, &debug_level, 0,
         _("Debug level"), NULL},
        {"debug-timestamps", 0, POPT_ARG_INT, &debug_timestamps, 0,
         _("Add debug timestamps"), NULL},
        {"debug-microseconds", 0, POPT_ARG_INT, &debug_microseconds, 0,
         _("Show timestamps with microseconds"), NULL},
        {"debug-fd", 0, POPT_ARG_INT, &debug_fd, 0,
         _("An open file descriptor for the debug logs"), NULL},
        {"debug-to-stderr", 0, POPT_ARG_NONE | POPT_ARGFLAG_DOC_HIDDEN,
         &debug_to_stderr, 0,
         _("Send the debug output to stderr directly."), NULL },
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
        fprintf(stderr, "\nInvalid option %s: %s\n\n",
                  poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            _exit(-1);
        }
    }

    poptFreeContext(pc);

    DEBUG_INIT(debug_level);

    debug_prg_name = talloc_asprintf(NULL, "[sssd[gpo_child[%d]]]", getpid());
    if (debug_prg_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        goto fail;
    }

    if (debug_fd != -1) {
        ret = set_debug_file_from_fd(debug_fd);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "set_debug_file_from_fd failed.\n");
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, "gpo_child started.\n");

    main_ctx = talloc_new(NULL);
    if (main_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new failed.\n");
        talloc_free(discard_const(debug_prg_name));
        goto fail;
    }
    talloc_steal(main_ctx, debug_prg_name);

    buf = talloc_size(main_ctx, sizeof(uint8_t)*IN_BUF_SIZE);
    if (buf == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        goto fail;
    }

    ibuf = talloc_zero(main_ctx, struct input_buffer);
    if (ibuf == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "context initialized\n");

    errno = 0;
    len = sss_atomic_read_s(STDIN_FILENO, buf, IN_BUF_SIZE);
    if (len == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "read failed [%d][%s].\n", ret, strerror(ret));
        goto fail;
    }

    close(STDIN_FILENO);

    ret = unpack_buffer(buf, len, ibuf);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "unpack_buffer failed.[%d][%s].\n", ret, strerror(ret));
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "processing security settings\n");

    result = process_security_settings_cse(main_ctx,
                                           ibuf->smb_uri,
                                           ibuf->unix_path);
    if (result != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "process_security_settings_cse failed.[%d][%s].\n",
              result, strerror(result));
    }

    ret = prepare_response(main_ctx, result, &resp);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "prepare_response failed. [%d][%s].\n",
                    ret, strerror(ret));
        goto fail;
    }

    errno = 0;

    written = sss_atomic_write_s(STDOUT_FILENO, resp->buf, resp->size);
    if (written == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "write failed [%d][%s].\n", ret,
                    strerror(ret));
        goto fail;
    }

    if (written != resp->size) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Expected to write %zu bytes, wrote %zu\n",
              resp->size, written);
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "gpo_child completed successfully\n");
    close(STDOUT_FILENO);
    talloc_free(main_ctx);
    return EXIT_SUCCESS;

fail:
    DEBUG(SSSDBG_CRIT_FAILURE, "gpo_child failed!\n");
    close(STDOUT_FILENO);
    talloc_free(main_ctx);
    return EXIT_FAILURE;
}
