/*
    SSSD

    IPA back end -- set SELinux context in a child module

    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

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


#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <popt.h>

#include "util/util.h"
#include "util/child_common.h"
#include "providers/backend.h"

struct input_buffer {
    const char *seuser;
    const char *mls_range;
    const char *username;
};

static errno_t unpack_buffer(uint8_t *buf,
                             size_t size,
                             struct input_buffer *ibuf)
{
    size_t p = 0;
    uint32_t len;

    /* seuser */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
    DEBUG(SSSDBG_TRACE_INTERNAL, "seuser length: %d\n", len);
    if (len == 0) {
        ibuf->seuser = "";
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Empty SELinux user, will delete the mapping\n");
    } else {
        if (len > size - p) return EINVAL;
        ibuf->seuser = talloc_strndup(ibuf, (char *)(buf + p), len);
        if (ibuf->seuser == NULL) return ENOMEM;
        DEBUG(SSSDBG_TRACE_INTERNAL, "seuser: %s\n", ibuf->seuser);
        p += len;
    }

    /* MLS range */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
    DEBUG(SSSDBG_TRACE_INTERNAL, "mls_range length: %d\n", len);
    if (len == 0) {
        if (strcmp(ibuf->seuser, "") != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "No MLS mapping!\n");
            return EINVAL;
        }
    } else {
        if (len > size - p) return EINVAL;
        ibuf->mls_range = talloc_strndup(ibuf, (char *)(buf + p), len);
        if (ibuf->mls_range == NULL) return ENOMEM;
        DEBUG(SSSDBG_TRACE_INTERNAL, "mls_range: %s\n", ibuf->mls_range);
        p += len;
    }

    /* username */
    SAFEALIGN_COPY_UINT32_CHECK(&len, buf + p, size, &p);
    DEBUG(SSSDBG_TRACE_INTERNAL, "username length: %d\n", len);
    if (len == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No username set!\n");
        return EINVAL;
    } else {
        if (len > size - p) return EINVAL;
        ibuf->username = talloc_strndup(ibuf, (char *)(buf + p), len);
        if (ibuf->username == NULL) return ENOMEM;
        DEBUG(SSSDBG_TRACE_INTERNAL, "username: %s\n", ibuf->username);
        p += len;
    }

    return EOK;
}

static errno_t pack_buffer(struct response *r, int result)
{
    size_t p = 0;

    /* A buffer with the following structure must be created:
     *   uint32_t status of the request (required)
     */
    r->size =  sizeof(uint32_t);

    r->buf = talloc_array(r, uint8_t, r->size);
    if(r->buf == NULL) {
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "result [%d]\n", result);

    /* result */
    SAFEALIGN_SET_UINT32(&r->buf[p], result, &p);

    return EOK;
}

static errno_t prepare_response(TALLOC_CTX *mem_ctx,
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
    DEBUG(SSSDBG_TRACE_ALL, "r->size: %zu\n", r->size);
    return EOK;
}

static int sc_set_seuser(const char *login_name, const char *seuser_name,
                         const char *mls)
{
    int ret;
    mode_t old_mask;

    /* This is a workaround for
     * https://bugzilla.redhat.com/show_bug.cgi?id=1186422 to make sure
     * the directories are created with the expected permissions
     */
    old_mask = umask(0);
    if (strcmp(seuser_name, "") == 0) {
        /* An empty SELinux user should cause SSSD to use the system
         * default. We need to remove the SELinux user from the DB
         * in that case
         */
        ret = sss_del_seuser(login_name);
    } else {
        ret = sss_set_seuser(login_name, seuser_name, mls);
    }
    umask(old_mask);
    return ret;
}

static bool seuser_needs_update(const char *username,
                                const char *seuser,
                                const char *mls_range)
{
    bool needs_update = true;
    char *db_seuser = NULL;
    char *db_mls_range = NULL;
    errno_t ret;

    ret = sss_get_seuser(username, &db_seuser, &db_mls_range);
    DEBUG(SSSDBG_TRACE_INTERNAL,
          "getseuserbyname: ret: %d seuser: %s mls: %s\n",
          ret, db_seuser ? db_seuser : "unknown",
          db_mls_range ? db_mls_range : "unknown");
    if (ret == EOK && db_seuser && db_mls_range &&
            strcmp(db_seuser, seuser) == 0 &&
            strcmp(db_mls_range, mls_range) == 0) {
        needs_update = false;
    }
    /* OR */
    if (ret == ERR_SELINUX_NOT_MANAGED) {
        needs_update = false;
    }

    free(db_seuser);
    free(db_mls_range);
    return needs_update;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int debug_fd = -1;
    errno_t ret;
    TALLOC_CTX *main_ctx = NULL;
    uint8_t *buf = NULL;
    ssize_t len = 0;
    struct input_buffer *ibuf = NULL;
    struct response *resp = NULL;
    struct passwd *passwd = NULL;
    ssize_t written;
    bool needs_update;
    const char *username;
    const char *opt_logger = NULL;

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
        SSSD_LOGGER_OPTS
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

    debug_prg_name = talloc_asprintf(NULL, "[sssd[selinux_child[%d]]]", getpid());
    if (debug_prg_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        goto fail;
    }

    if (debug_fd != -1) {
        ret = set_debug_file_from_fd(debug_fd);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "set_debug_file_from_fd failed.\n");
        }
        opt_logger = sss_logger_str[FILES_LOGGER];
    }

    sss_set_logger(opt_logger);

    DEBUG(SSSDBG_TRACE_FUNC, "selinux_child started.\n");
    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Running with effective IDs: [%"SPRIuid"][%"SPRIgid"].\n",
          geteuid(), getegid());

    /* The functions semanage_genhomedircon and getseuserbyname use gepwnam_r
     * and they might fail to return values if they are not in memory cache.
     *   [main] (0x0400): performing selinux operations
     *   [seuser_needs_update] (0x2000): getseuserbyname: ret: 0
     *                                   seuser: unconfined_u mls: s0-s0:c0.c15
     *   [libsemanage] (0x0020): semanage_genhomedircon returned error code -1.
     *   [sss_set_seuser] (0x0020): Cannot commit SELinux transaction
     *   [main] (0x0020): Cannot set SELinux login context.
     *   [main] (0x0020): selinux_child failed!
     */
    if (unsetenv("_SSS_LOOPS") != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to unset _SSS_LOOPS, some libsemanage functions might "
              "fail.\n");
    }

    /* libsemanage calls access(2) which works with real IDs, not effective.
     * We need to switch also the real ID to 0.
     */
    if (getuid() != 0) {
        ret = setuid(0);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "setuid failed: %d, selinux_child might not work!\n", ret);
        }
    }

    if (getgid() != 0) {
        ret = setgid(0);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "setgid failed: %d, selinux_child might not work!\n", ret);
        }
    }

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Running with real IDs [%"SPRIuid"][%"SPRIgid"].\n",
          getuid(), getgid());

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

    DEBUG(SSSDBG_TRACE_FUNC, "performing selinux operations\n");

    /* When using domain_resolution_order the username will always be
     * fully-qualified, what has been causing some SELinux issues as mappings
     * for user 'admin' are not applied for 'admin@ipa.example'.
     *
     * In order to work this around we can take advantage that selinux_child
     * queries SSSD since commit 92addd7ba and call getpwnam() in order to get
     * the username in the correct format. */
    passwd = getpwnam(ibuf->username);
    if (passwd == NULL) {
        username = ibuf->username;
        DEBUG(SSSDBG_MINOR_FAILURE,
              "getpwnam() failed to get info for the user \"%s\". SELinux label "
              "setting might fail as well!\n",
              ibuf->username);
    } else {
        username = passwd->pw_name;
    }

    needs_update = seuser_needs_update(username, ibuf->seuser,
                                       ibuf->mls_range);
    if (needs_update == true) {
        ret = sc_set_seuser(username, ibuf->seuser, ibuf->mls_range);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot set SELinux login context.\n");
            goto fail;
        }
    }

    ret = prepare_response(main_ctx, ret, &resp);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to prepare response buffer.\n");
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

    DEBUG(SSSDBG_TRACE_FUNC, "selinux_child completed successfully\n");
    close(STDOUT_FILENO);
    talloc_free(main_ctx);
    return EXIT_SUCCESS;
fail:
    DEBUG(SSSDBG_CRIT_FAILURE, "selinux_child failed!\n");
    close(STDOUT_FILENO);
    talloc_free(main_ctx);
    return EXIT_FAILURE;
}
