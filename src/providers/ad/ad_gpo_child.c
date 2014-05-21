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
#include <ini_configobj.h>
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
};

static errno_t
unpack_buffer(uint8_t *buf,
              size_t size,
              struct input_buffer *ibuf)
{
    size_t p = 0;
    uint32_t len;

    DEBUG(SSSDBG_TRACE_FUNC, "total buffer size: %zu\n", size);

    /* smb_uri size and length */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);

    DEBUG(SSSDBG_TRACE_FUNC, "smb_uri size: %d\n", len);

    if (len == 0) {
        return EINVAL;
    } else {
        if ((p + len ) > size) return EINVAL;
        ibuf->smb_uri = talloc_strndup(ibuf, (char *)(buf + p), len);
        if (ibuf->smb_uri == NULL) return ENOMEM;
        DEBUG(SSSDBG_TRACE_FUNC, "got smb_uri: %s\n", ibuf->smb_uri);
        p += len;
    }

    return EOK;
}


static errno_t
pack_buffer(struct response *r,
            int result,
            int allowed_size,
            char **allowed_sids,
            int denied_size,
            char **denied_sids)
{
    int len = 0;
    size_t p = 0;
    int i;
    int sid_len = 0;

    /* A buffer with the following structure must be created:
     *   uint32_t status of the request (required)
     *   uint32_t allowed_size (required)
     *   sid_message* (allowed_size instances)
     *   uint32_t denied_size (required)
     *   sid_message* (denied_size instances)
     *
     * A sid_message consists of:
     *   uint32_t sid_len
     *   uint8_t[sid_len] sid string
     */

    DEBUG(SSSDBG_TRACE_FUNC, "entering pack_buffer\n");

    for (i = 0; i < allowed_size; i++) {
        len += strlen(allowed_sids[i]);
    }

    for (i = 0; i < denied_size; i++) {
        len += strlen(denied_sids[i]);
    }

    r->size = (3 + allowed_size + denied_size) * sizeof(uint32_t) + len;

    DEBUG(SSSDBG_TRACE_FUNC, "response size: %zu\n",r->size);

    r->buf = talloc_array(r, uint8_t, r->size);
    if(r->buf == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "result [%d] allowed_size [%d] denied_size [%d]\n",
          result, allowed_size, denied_size);

    /* result */
    SAFEALIGN_SET_UINT32(&r->buf[p], result, &p);

    /* allowed_size */
    SAFEALIGN_SET_UINT32(&r->buf[p], allowed_size, &p);

    /* allowed_sids */
    for (i = 0; i < allowed_size; i++) {
        sid_len = strlen(allowed_sids[i]);
        SAFEALIGN_SET_UINT32(&r->buf[p], sid_len, &p);
        safealign_memcpy(&r->buf[p], allowed_sids[i], sid_len, &p);
    }

    /* denied_size */
    SAFEALIGN_SET_UINT32(&r->buf[p], denied_size, &p);

    /* denied_sids */
    for (i = 0; i < denied_size; i++) {
        sid_len = strlen(denied_sids[i]);
        SAFEALIGN_SET_UINT32(&r->buf[p], sid_len, &p);
        safealign_memcpy(&r->buf[p], denied_sids[i], sid_len, &p);
    }

    return EOK;
}

static errno_t
prepare_response(TALLOC_CTX *mem_ctx,
                 int result,
                 int allowed_size,
                 char **allowed_sids,
                 int denied_size,
                 char **denied_sids,
                 struct response **rsp)
{
    int ret;
    struct response *r = NULL;

    DEBUG(SSSDBG_TRACE_FUNC, "entering prepare_response.\n");
    r = talloc_zero(mem_ctx, struct response);
    if (r == NULL) {
        return ENOMEM;
    }

    r->buf = NULL;
    r->size = 0;

    ret = pack_buffer(r, result, allowed_size, allowed_sids, denied_size, denied_sids);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pack_buffer failed\n");
        return ret;
    }

    *rsp = r;
    DEBUG(SSSDBG_TRACE_FUNC, "r->size: %zu\n", r->size);
    return EOK;
}

/*
 * This function uses the input ini_config object to parse the logon right value
 * associated with the input name. This value is a list of sids, and is used
 * to populate the output parameters. The input name can be either
 * ALLOW_LOGON_LOCALLY or DENY_LOGON_LOCALLY.
 */
static errno_t
parse_logon_right_with_libini(TALLOC_CTX *mem_ctx,
                              struct ini_cfgobj *ini_config,
                              const char *name,
                              int *_size,
                              char ***_sids)
{
    int ret = 0;
    struct value_obj *vobj = NULL;
    char **ini_sids = NULL;
    char *ini_sid = NULL;
    int num_ini_sids = 0;
    char **sids = NULL;
    int i;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ini_get_config_valueobj(RIGHTS_SECTION, name, ini_config,
                                  INI_GET_FIRST_VALUE, &vobj);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ini_get_config_valueobj failed [%d][%s]\n", ret, strerror(ret));
        goto done;
    }
    if (vobj == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "section/name not found: [%s][%s]\n",
              RIGHTS_SECTION, name);
        ret = EOK;
        goto done;
    }
    ini_sids = ini_get_string_config_array(vobj, NULL, &num_ini_sids, &ret);

    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ini_get_string_config_array failed [%d][%s]\n", ret, strerror(ret));
        goto done;
    }

    sids = talloc_array(tmp_ctx, char *, num_ini_sids + 1);
    if (sids == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_ini_sids; i++) {
        ini_sid = ini_sids[i];

        /* remove the asterisk prefix found on sids in the .inf policy file */
        if (ini_sid[0] == '*') {
            ini_sid++;
        }
        sids[i] = talloc_strdup(sids, ini_sid);
        if (sids[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }
    sids[i] = NULL;

    *_size = num_ini_sids;
    *_sids = talloc_steal(mem_ctx, sids);

    ret = EOK;

 done:

    ini_free_string_config_array(ini_sids);
    talloc_free(tmp_ctx);
    return ret;
}

/*
 * This function parses the cse-specific (GP_EXT_GUID_SECURITY) input data_buf,
 * and uses the results to populate the output parameters with the list of
 * allowed_sids and denied_sids
 */
static errno_t
ad_gpo_parse_security_cse_buffer(TALLOC_CTX *mem_ctx,
                                 uint8_t *data_buf,
                                 int data_len,
                                 char ***allowed_sids,
                                 int *allowed_size,
                                 char ***denied_sids,
                                 int *denied_size)
{
    struct ini_cfgfile *file_ctx = NULL;
    struct ini_cfgobj *ini_config = NULL;
    int ret;
    char **allow_sids = NULL;
    char **deny_sids = NULL;
    int allow_size = 0;
    int deny_size = 0;
    const char *key = NULL;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = ini_config_create(&ini_config);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ini_config_create failed [%d][%s]\n", ret, strerror(ret));
        goto done;
    }

    ret = ini_config_file_from_mem(data_buf, data_len, &file_ctx);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ini_config_file_from_mem failed [%d][%s]\n", ret, strerror(ret));
        goto done;
    }

    ret = ini_config_parse(file_ctx, INI_STOP_ON_NONE, 0, 0, ini_config);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ini_config_parse failed [%d][%s]\n", ret, strerror(ret));
        goto done;
    }

    key = ALLOW_LOGON_LOCALLY;
    ret = parse_logon_right_with_libini(tmp_ctx,
                                        ini_config,
                                        key,
                                        &allow_size,
                                        &allow_sids);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "parse_logon_right_with_libini failed for %s [%d][%s]\n",
              key, ret, strerror(ret));
        goto done;
    }

    key = DENY_LOGON_LOCALLY;
    ret = parse_logon_right_with_libini(tmp_ctx,
                                        ini_config,
                                        DENY_LOGON_LOCALLY,
                                        &deny_size,
                                        &deny_sids);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "parse_logon_right_with_libini failed for %s [%d][%s]\n",
              key, ret, strerror(ret));
        goto done;
    }

    *allowed_sids = talloc_steal(mem_ctx, allow_sids);
    *allowed_size = allow_size;
    *denied_sids = talloc_steal(mem_ctx, deny_sids);
    *denied_size = deny_size;

 done:

    if (ret != EOK) {
      DEBUG(SSSDBG_CRIT_FAILURE, "Error encountered: %d.\n", ret);
    }

    ini_config_file_destroy(file_ctx);
    ini_config_destroy(ini_config);
    talloc_free(tmp_ctx);
    return ret;
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
 * This cse-specific function (GP_EXT_GUID_SECURITY) opens an SMB connection,
 * retrieves the data referenced by the input smb_uri, and then closes the SMB
 * connection. The data is then parsed and the results are used to populate the
 * output parameters with the list of allowed_sids and denied_sids
 */
static errno_t
process_security_settings_cse(TALLOC_CTX *mem_ctx,
                              const char *smb_uri,
                              char ***_allowed_sids,
                              int *_allowed_size,
                              char ***_denied_sids,
                              int *_denied_size)
{
    SMBCCTX *context;
    int ret = 0;
    uint8_t *buf = NULL;
    int bytesread = 0;
    char **allowed_sids;
    char **denied_sids;
    int allowed_size = 0;
    int denied_size = 0;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_ALL, "%s\n", smb_uri);

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
    bytesread = smbc_read(remotehandle, buf, SMB_BUFFER_SIZE);
    if(bytesread < 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "smbc_read failed\n");
        ret = EPIPE;
        goto done;
    }

    DEBUG(SSSDBG_CRIT_FAILURE, "bytesread: %d\n", bytesread);

    smbc_close(remotehandle);

    ret = ad_gpo_parse_security_cse_buffer(tmp_ctx,
                                           buf,
                                           bytesread,
                                           &allowed_sids,
                                           &allowed_size,
                                           &denied_sids,
                                           &denied_size);

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ad_gpo_parse_security_cse_buffer failed [%d][%s]\n",
              ret, strerror(ret));
        goto done;
    }

    /* TBD: allowed/denied_sids/size should be stored in cache */

    *_allowed_sids = talloc_steal(mem_ctx, allowed_sids);
    *_allowed_size = allowed_size;
    *_denied_sids = talloc_steal(mem_ctx, denied_sids);
    *_denied_size = denied_size;

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
    char **allowed_sids;
    int allowed_size;
    char **denied_sids;
    int denied_size;
    int j;

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
                                           &allowed_sids,
                                           &allowed_size,
                                           &denied_sids,
                                           &denied_size);
    if (result != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "process_security_settings_cse failed.[%d][%s].\n",
              ret, strerror(ret));
        goto fail;
    }

    DEBUG(SSSDBG_CRIT_FAILURE, "allowed_size = %d\n", allowed_size);
    for (j= 0; j < allowed_size; j++) {
        DEBUG(SSSDBG_CRIT_FAILURE, "allowed_sids[%d] = %s\n", j,
              allowed_sids[j]);
    }

    DEBUG(SSSDBG_CRIT_FAILURE, "denied_size = %d\n", denied_size);
    for (j= 0; j < denied_size; j++) {
        DEBUG(SSSDBG_CRIT_FAILURE, " denied_sids[%d] = %s\n", j,
              denied_sids[j]);
    }

    ret = prepare_response(main_ctx, result, allowed_size, allowed_sids, denied_size, denied_sids, &resp);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "prepare_response failed. [%d][%s].\n",
                    ret, strerror(ret));
        goto fail;
    }

    errno = 0;
    DEBUG(SSSDBG_TRACE_FUNC, "resp->size: %zu\n", resp->size);

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
