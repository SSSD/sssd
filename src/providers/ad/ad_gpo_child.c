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
#include <ctype.h>
#include <unistd.h>
#include <popt.h>
#include <libsmbclient.h>
#include <security/pam_modules.h>

#include "util/child_bootstrap.h"
#include "shared/io.h"
#include "util/util.h"
#include "util/sss_chain_id.h"
#include "util/sss_prctl.h"
#include "providers/backend.h"
#include "providers/ad/ad_gpo.h"
#include "sss_cli.h"

#define SMB_BUFFER_SIZE 65536
#define GPT_INI "/GPT.INI"

errno_t ad_gpo_parse_ini_file(const char *smb_path, int *_gpt_version);

struct input_buffer {
    int cached_gpt_version;
    const char *smb_server;
    const char *smb_share;
    const char *smb_path;
    const char *smb_cse_suffix;
};

static errno_t
unpack_buffer(uint8_t *buf,
              size_t size,
              struct input_buffer *ibuf)
{
    size_t p = 0;
    uint32_t len;
    uint32_t cached_gpt_version;

    /* cached_gpt_version */
    SAFEALIGN_COPY_UINT32_CHECK(&cached_gpt_version, buf + p, size, &p);
    DEBUG(SSSDBG_TRACE_FUNC, "cached_gpt_version: %d\n", cached_gpt_version);
    ibuf->cached_gpt_version = cached_gpt_version;

    /* smb_server */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
    DEBUG(SSSDBG_TRACE_ALL, "smb_server length: %d\n", len);
    if (len == 0) {
        return EINVAL;
    } else {
        if (len > size - p) return EINVAL;
        ibuf->smb_server = talloc_strndup(ibuf, (char *)(buf + p), len);
        if (ibuf->smb_server == NULL) return ENOMEM;
        DEBUG(SSSDBG_TRACE_ALL, "smb_server: %s\n", ibuf->smb_server);
        p += len;
    }

    /* smb_share */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
    DEBUG(SSSDBG_TRACE_ALL, "smb_share length: %d\n", len);
    if (len == 0) {
        return EINVAL;
    } else {
        if (len > size - p) return EINVAL;
        ibuf->smb_share = talloc_strndup(ibuf, (char *)(buf + p), len);
        if (ibuf->smb_share == NULL) return ENOMEM;
        DEBUG(SSSDBG_TRACE_ALL, "smb_share: %s\n", ibuf->smb_share);
        p += len;
    }

    /* smb_path */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
    DEBUG(SSSDBG_TRACE_ALL, "smb_path length: %d\n", len);
    if (len == 0) {
        return EINVAL;
    } else {
        if (len > size - p) return EINVAL;
        ibuf->smb_path = talloc_strndup(ibuf, (char *)(buf + p), len);
        if (ibuf->smb_path == NULL) return ENOMEM;
        DEBUG(SSSDBG_TRACE_ALL, "smb_path: %s\n", ibuf->smb_path);
        p += len;
    }

    /* smb_cse_suffix */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
    DEBUG(SSSDBG_TRACE_ALL, "smb_cse_suffix length: %d\n", len);
    if (len == 0) {
        return EINVAL;
    } else {
        if (len > size - p) return EINVAL;
        ibuf->smb_cse_suffix = talloc_strndup(ibuf, (char *)(buf + p), len);
        if (ibuf->smb_cse_suffix == NULL) return ENOMEM;
        DEBUG(SSSDBG_TRACE_ALL, "smb_cse_suffix: %s\n", ibuf->smb_cse_suffix);
        p += len;
    }

    return EOK;
}


static errno_t
pack_buffer(struct io_buffer *r,
            int sysvol_gpt_version,
            int result)
{
    size_t p = 0;

    /* A buffer with the following structure must be created:
     *   uint32_t sysvol_gpt_version (required)
     *   uint32_t status of the request (required)
     */
    r->size = 2 * sizeof(uint32_t);

    r->data = talloc_array(r, uint8_t, r->size);
    if (r->data == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "result [%d]\n", result);

    /* sysvol_gpt_version */
    SAFEALIGN_SET_UINT32(&r->data[p], sysvol_gpt_version, &p);

    /* result */
    SAFEALIGN_SET_UINT32(&r->data[p], result, &p);

    return EOK;
}

static errno_t
prepare_response(TALLOC_CTX *mem_ctx,
                 int sysvol_gpt_version,
                 int result,
                 struct io_buffer **rsp)
{
    int ret;
    struct io_buffer *r = NULL;

    r = talloc_zero(mem_ctx, struct io_buffer);
    if (r == NULL) {
        return ENOMEM;
    }

    r->data = NULL;
    r->size = 0;

    ret = pack_buffer(r, sysvol_gpt_version, result);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pack_buffer failed\n");
        return ret;
    }

    *rsp = r;
    DEBUG(SSSDBG_TRACE_ALL, "r->size: %zu\n", r->size);
    return EOK;
}

static void
sssd_krb_get_auth_data_fn(SMBCCTX *ctx,
                          const char * pServer,
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
 * - parsing the input_smb_path into its component directories
 * - creating each component directory (if it doesn't already exist)
 */
static errno_t prepare_gpo_cache(TALLOC_CTX *mem_ctx,
                                 const char *cache_dir,
                                 const char *input_smb_path_with_suffix)
{
    char *current_dir;
    char *ptr;
    const char delim = '/';
    int num_dirs = 0;
    int i;
    char *first = NULL;
    char *last = NULL;
    char *smb_path_with_suffix = NULL;
    errno_t ret;
    mode_t old_umask;

    smb_path_with_suffix = talloc_strdup(mem_ctx, input_smb_path_with_suffix);
    if (smb_path_with_suffix == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_ALL, "smb_path_with_suffix: %s\n", smb_path_with_suffix);

    current_dir = talloc_strdup(mem_ctx, cache_dir);
    if (current_dir == NULL) {
        return ENOMEM;
    }

    ptr = smb_path_with_suffix + 1;
    while ((ptr = strchr(ptr, delim))) {
        ptr++;
        num_dirs++;
    }

    ptr = smb_path_with_suffix + 1;

    old_umask = umask(SSS_DFL_X_UMASK);
    for (i = 0; i < num_dirs; i++) {
        first = ptr;
        last = strchr(first, delim);
        if (last == NULL) {
            ret = EINVAL;
            goto done;
        }
        *last = '\0';
        last++;

        current_dir = talloc_asprintf(mem_ctx, "%s/%s", current_dir, first);
        if (current_dir == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
            ret = ENOMEM;
            goto done;
        }
        DEBUG(SSSDBG_TRACE_FUNC, "Storing GPOs in %s\n", current_dir);

        if ((mkdir(current_dir, 0700)) < 0 && errno != EEXIST) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "mkdir(%s) failed: %d\n", current_dir, ret);
            goto done;
        }

        ptr = last;
    }

    ret = EOK;

done:
    umask(old_umask);

    return ret;
}

/*
 * This function stores the input buf to a local file, whose file path
 * is constructed by concatenating:
 *   GPO_CACHE_PATH,
 *   input smb_path,
 *   input smb_cse_suffix
 * Note that the backend will later read the file from the same file path.
 */
static errno_t gpo_cache_store_file(const char *smb_path,
                                    const char *smb_cse_suffix,
                                    uint8_t *buf,
                                    int buflen)
{
    int ret;
    int fret;
    int fd = -1;
    char *tmp_name = NULL;
    ssize_t written;
    char *filename = NULL;
    char *smb_path_with_suffix = NULL;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    smb_path_with_suffix =
        talloc_asprintf(tmp_ctx, "%s%s", smb_path, smb_cse_suffix);
    if (smb_path_with_suffix == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    /* create component directories of smb_path, if needed */
    ret = prepare_gpo_cache(tmp_ctx, GPO_CACHE_PATH, smb_path_with_suffix);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "prepare_gpo_cache failed [%d][%s]\n",
              ret, strerror(ret));
        goto done;
    }

    filename = talloc_asprintf(tmp_ctx, GPO_CACHE_PATH"%s", smb_path_with_suffix);
    if (filename == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    tmp_name = talloc_asprintf(tmp_ctx, "%sXXXXXX", filename);
    if (tmp_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    fd = sss_unique_file(tmp_ctx, tmp_name, &ret);
    if (fd == -1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sss_unique_file failed [%d][%s].\n", ret, strerror(ret));
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

    ret = rename(tmp_name, filename);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "rename failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    ret = EOK;
 done:
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Error encountered: %d.\n", ret);
    }

    if (fd != -1) {
        fret = close(fd);
        if (fret == -1) {
            fret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "close failed [%d][%s].\n", fret, strerror(fret));
        }
    }

    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
gpo_cache_remove_file(const char *smb_path,
                      const char *smb_cse_suffix)
{
    errno_t ret = EOK;
    char *filename = NULL;

    filename = talloc_asprintf(NULL, GPO_CACHE_PATH"%s%s", smb_path,
                                                           smb_cse_suffix);
    if (filename == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = unlink(filename);
    if (ret != 0) {
        if (errno != ENOENT) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE, "failed to unlink %s [%d]: %s\n",
                                       filename, ret, sss_strerror(ret));
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(filename);
    return ret;
}

/*
 * This function uses the input smb uri components to download a sysvol file
 * (e.g. INI file, policy file, etc) and store it to the GPO_CACHE directory.
 */
static errno_t
copy_smb_file_to_gpo_cache(SMBCCTX *smbc_ctx,
                           const char *smb_server,
                           const char *smb_share,
                           const char *smb_path,
                           const char *smb_cse_suffix,
                           bool optional)
{
    char *smb_uri = NULL;
    char *gpt_main_folder = NULL;
    SMBCFILE *file = NULL;
    int ret;
    uint8_t *buf = NULL;
    int buflen = 0;

    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    smb_uri = talloc_asprintf(tmp_ctx, "%s%s%s%s", smb_server,
                              smb_share, smb_path, smb_cse_suffix);
    if (smb_uri == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "smb_uri: %s\n", smb_uri);

    errno = 0;
    file = smbc_getFunctionOpen(smbc_ctx)(smbc_ctx, smb_uri, O_RDONLY, 0755);
    if (file == NULL) {
        // ENOENT: A directory component in pathname does not exist
        if (errno == ENOENT) {
            /*
             * DCs may use upper case names for the main folder, where GPTs are
             * stored. libsmbclient does not allow us to request case insensitive
             * file name lookups on DCs with case sensitive file systems.
             */
            gpt_main_folder = strstr(smb_uri, "/Machine/");
            if (gpt_main_folder == NULL) {
                /* At this moment we do not use any GPO from user settings,
                 * but it can change in the future so let's keep the following
                 * line around to make this part of the code 'just work' also
                 * with the user GPO settings. */
                gpt_main_folder = strstr(smb_uri, "/User/");
            }
            if (gpt_main_folder != NULL) {
                ++gpt_main_folder;
                while (gpt_main_folder != NULL && *gpt_main_folder != '/') {
                    *gpt_main_folder = toupper(*gpt_main_folder);
                    ++gpt_main_folder;
                }

                DEBUG(SSSDBG_TRACE_FUNC, "smb_uri: %s\n", smb_uri);

                errno = 0;
                file = smbc_getFunctionOpen(smbc_ctx)(smbc_ctx, smb_uri, O_RDONLY, 0755);
            }
        }

        if (file == NULL) {
            ret = errno;
            if (optional && ret == ENOENT) {
                DEBUG(SSSDBG_TRACE_FUNC,
                      "%s does not exist in sysvol, purging cached copy\n",
                      smb_uri);
                /* It looks like Windows clients treat missing GPO files as
                 * empty. To make sure we do not use old and now invalid
                 * content an potentially exising old file will be removed. */
                ret = gpo_cache_remove_file(smb_path, smb_cse_suffix);
                if (ret != EOK && ret != ENOENT) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "failed to purge stale cached %s\n", smb_uri);
                    goto done;
                }
                ret = EOK;
            } else {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "smbc_getFunctionOpen failed [%d][%s]\n",
                      ret, strerror(ret));
            }
            goto done;
        }
    }

    buf = talloc_array(tmp_ctx, uint8_t, SMB_BUFFER_SIZE);
    if (buf == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    errno = 0;
    buflen = smbc_getFunctionRead(smbc_ctx)(smbc_ctx, file, buf, SMB_BUFFER_SIZE);
    if (buflen < 0) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "smbc_getFunctionRead failed [%d][%s]\n",
              ret, strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "smb_buflen: %d\n", buflen);

    ret = gpo_cache_store_file(smb_path, smb_cse_suffix, buf, buflen);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "gpo_cache_store_file failed [%d][%s]\n",
              ret, strerror(ret));
        goto done;
    }

 done:
    if (file != NULL) {
        smbc_getFunctionClose(smbc_ctx)(smbc_ctx, file);
    }

    talloc_free(tmp_ctx);
    return ret;
}


/*
 * Using its smb_uri components and cached_gpt_version inputs, this function
 * does several things:
 * - it downloads the GPT_INI file to GPO_CACHE
 * - it parses the sysvol_gpt_version field from the GPT_INI file
 * - if the sysvol_gpt_version is greater than the cached_gpt_version
 *   - it downloads the policy file to GPO_CACHE
 * - else
 *   - it doesn't retrieve the policy file
 *   - in this case, the backend will use the existing policy file in GPO_CACHE
 * - it returns the sysvol_gpt_version in the _sysvol_gpt_version output param
 *
 * Note that if the cached_gpt_version sent by the backend is -1 (to indicate
 * that no gpt_version has been set in the cache for the corresponding gpo_guid),
 * then the parsed sysvol_gpt_version (which must be at least 0) will be greater
 * than the cached_gpt_version, thereby triggering a fresh download.
 *
 * Note that the backend will later do the following:
 * - backend will save the sysvol_gpt_version to sysdb cache
 * - backend will read the policy file from the GPO_CACHE
 */
static errno_t
perform_smb_operations(int cached_gpt_version,
                       const char *smb_server,
                       const char *smb_share,
                       const char *smb_path,
                       const char *smb_cse_suffix,
                       int *_sysvol_gpt_version)
{
    SMBCCTX *smbc_ctx;
    int ret;
    int sysvol_gpt_version = -1;
    char *ini_filename = NULL;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    smbc_ctx = smbc_new_context();
    if (smbc_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not allocate new smbc context\n");
        ret = ENOMEM;
        goto done;
    }

    smbc_setOptionDebugToStderr(smbc_ctx, true);
    smbc_setFunctionAuthDataWithContext(smbc_ctx, sssd_krb_get_auth_data_fn);
    smbc_setOptionUseKerberos(smbc_ctx, true);
    smbc_setOptionFallbackAfterKerberos(smbc_ctx, false);

    /* Initialize the context using the previously specified options */
    if (smbc_init_context(smbc_ctx) == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not initialize smbc context\n");
        ret = ENOMEM;
        goto done;
    }

    /* download ini file */
    ret = copy_smb_file_to_gpo_cache(smbc_ctx, smb_server, smb_share, smb_path,
                                     GPT_INI, false);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "copy_smb_file_to_gpo_cache failed [%d][%s]\n",
              ret, strerror(ret));
        goto done;
    }

    ini_filename = talloc_asprintf(tmp_ctx, GPO_CACHE_PATH"%s"GPT_INI, smb_path);
    if (ini_filename == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = ad_gpo_parse_ini_file(ini_filename, &sysvol_gpt_version);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot parse ini file: [%d][%s]\n", ret, strerror(ret));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "sysvol_gpt_version: %d\n", sysvol_gpt_version);

    if (sysvol_gpt_version > cached_gpt_version) {
        /* download policy file */
        ret = copy_smb_file_to_gpo_cache(smbc_ctx, smb_server, smb_share,
                                         smb_path, smb_cse_suffix, true);
        if (ret != EOK && ret != ENOENT) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "copy_smb_file_to_gpo_cache failed [%d][%s]\n",
                  ret, strerror(ret));
            goto done;
        }
        ret = EOK;
    }

    *_sysvol_gpt_version = sysvol_gpt_version;

 done:
    talloc_free(tmp_ctx);
    smbc_free_context(smbc_ctx, 0);
    return ret;
}

int
main(int argc, const char *argv[])
{
    static const size_t IN_BUF_SIZE = 2048;
    int opt;
    poptContext pc;
    errno_t ret;
    int sysvol_gpt_version = -1;
    int result;
    TALLOC_CTX *main_ctx = NULL;
    uint8_t *buf = NULL;
    ssize_t len = 0;
    struct input_buffer *ibuf = NULL;
    struct io_buffer *resp = NULL;
    ssize_t written;

    struct poptOption long_options[] = {
        SSSD_BASIC_CHILD_OPTS
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

    sss_child_basic_settings.name = "gpo_child";
    if (!sss_child_setup_basics(&sss_child_basic_settings)) {
        _exit(-1);
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

    DEBUG(SSSDBG_TRACE_FUNC, "performing smb operations\n");

    result = perform_smb_operations(ibuf->cached_gpt_version,
                                    ibuf->smb_server,
                                    ibuf->smb_share,
                                    ibuf->smb_path,
                                    ibuf->smb_cse_suffix,
                                    &sysvol_gpt_version);
    if (result != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "perform_smb_operations failed.[%d][%s].\n",
              result, strerror(result));
        goto fail;
    }

    if (sysvol_gpt_version < 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "get sysvol_gpt_version failed. [%d].\n",
              sysvol_gpt_version);
        goto fail;
    }

    ret = prepare_response(main_ctx, sysvol_gpt_version, result, &resp);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "prepare_response failed. [%d][%s].\n",
                    ret, strerror(ret));
        goto fail;
    }

    errno = 0;

    written = sss_atomic_write_s(AD_GPO_CHILD_OUT_FILENO, resp->data, resp->size);
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
    close(AD_GPO_CHILD_OUT_FILENO);
    talloc_free(main_ctx);
    return EXIT_SUCCESS;

fail:
    DEBUG(SSSDBG_CRIT_FAILURE, "gpo_child failed!\n");
    close(AD_GPO_CHILD_OUT_FILENO);
    talloc_free(main_ctx);
    return EXIT_FAILURE;
}
