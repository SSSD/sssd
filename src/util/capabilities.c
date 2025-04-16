/*
   SSSD

   Capabilities management helpers

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

#include "config.h"
#include "util/util.h"

#ifdef HAVE_SYS_CAPABILITY_H

#include <unistd.h>
#include <linux/securebits.h>


typedef struct _cap_description
{
    cap_value_t val;
    const char *name;
} cap_description;

#define _CAP_DESCR(cap) {cap, #cap}

static cap_description _all_caps[] =
{
    _CAP_DESCR(CAP_AUDIT_CONTROL),
    _CAP_DESCR(CAP_AUDIT_READ),
    _CAP_DESCR(CAP_AUDIT_WRITE),
    _CAP_DESCR(CAP_BLOCK_SUSPEND),
    _CAP_DESCR(CAP_BPF),
    _CAP_DESCR(CAP_CHECKPOINT_RESTORE),
    _CAP_DESCR(CAP_CHOWN),
    _CAP_DESCR(CAP_DAC_OVERRIDE),
    _CAP_DESCR(CAP_DAC_READ_SEARCH),
    _CAP_DESCR(CAP_FOWNER),
    _CAP_DESCR(CAP_FSETID),
    _CAP_DESCR(CAP_IPC_LOCK),
    _CAP_DESCR(CAP_IPC_OWNER),
    _CAP_DESCR(CAP_KILL),
    _CAP_DESCR(CAP_LEASE),
    _CAP_DESCR(CAP_LINUX_IMMUTABLE),
    _CAP_DESCR(CAP_MAC_ADMIN),
    _CAP_DESCR(CAP_MAC_OVERRIDE),
    _CAP_DESCR(CAP_MKNOD),
    _CAP_DESCR(CAP_NET_ADMIN),
    _CAP_DESCR(CAP_NET_BIND_SERVICE),
    _CAP_DESCR(CAP_NET_BROADCAST),
    _CAP_DESCR(CAP_NET_RAW),
    _CAP_DESCR(CAP_PERFMON),
    _CAP_DESCR(CAP_SETGID),
    _CAP_DESCR(CAP_SETFCAP),
    _CAP_DESCR(CAP_SETPCAP),
    _CAP_DESCR(CAP_SETUID),
    _CAP_DESCR(CAP_SYS_ADMIN),
    _CAP_DESCR(CAP_SYS_BOOT),
    _CAP_DESCR(CAP_SYS_CHROOT),
    _CAP_DESCR(CAP_SYS_MODULE),
    _CAP_DESCR(CAP_SYS_NICE),
    _CAP_DESCR(CAP_SYS_PACCT),
    _CAP_DESCR(CAP_SYS_PTRACE),
    _CAP_DESCR(CAP_SYS_RAWIO),
    _CAP_DESCR(CAP_SYS_RESOURCE),
    _CAP_DESCR(CAP_SYS_TIME),
    _CAP_DESCR(CAP_SYS_TTY_CONFIG),
    _CAP_DESCR(CAP_SYSLOG),
    _CAP_DESCR(CAP_WAKE_ALARM)
};

static inline const char *cap_flag_to_str(cap_flag_value_t flag)
{
    if (flag == CAP_SET) {
        return "*1*";
    }
    return " 0 ";
}

errno_t sss_log_caps_to_str(bool only_non_zero, char **_str)
{
    int ret;
    char *str = NULL;
    size_t i;
    cap_t caps;
    cap_flag_value_t effective, permitted, inheritable, bounding;

    caps = cap_get_proc();
    if (caps == NULL) {
        ret = errno;
        DEBUG(SSSDBG_TRACE_FUNC, "cap_get_proc() failed: %d ('%s')\n",
              ret, strerror(ret));
        return ret;
    }

    for (i = 0; i < sizeof(_all_caps)/sizeof(cap_description); ++i) {
        if (!CAP_IS_SUPPORTED(_all_caps[i].val)) {
            continue;
        }
        ret = cap_get_flag(caps, _all_caps[i].val, CAP_EFFECTIVE, &effective);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_TRACE_FUNC,
                  "cap_get_flag(CAP_EFFECTIVE) failed: %d ('%s')\n",
                  ret, strerror(ret));
            goto done;
        }
        ret = cap_get_flag(caps, _all_caps[i].val, CAP_PERMITTED, &permitted);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_TRACE_FUNC,
                  "cap_get_flag(CAP_PERMITTED) failed: %d ('%s')\n",
                  ret, strerror(ret));
            goto done;
        }
        ret = cap_get_flag(caps, _all_caps[i].val, CAP_INHERITABLE, &inheritable);
        if (ret == -1) {
            ret = errno;
            DEBUG(SSSDBG_TRACE_FUNC,
                  "cap_get_flag(CAP_INHERITABLE) failed: %d ('%s')\n",
                  ret, strerror(ret));
            goto done;
        }
        ret = cap_get_bound(_all_caps[i].val);
        if (ret == 1) {
            bounding = CAP_SET;
        } else if (ret == 0) {
            bounding = CAP_CLEAR;
        } else {
            ret = errno;
            DEBUG(SSSDBG_TRACE_FUNC, "cap_get_bound failed: %d ('%s')\n",
                  ret, strerror(ret));
            goto done;
        }

        if (only_non_zero && (effective == CAP_CLEAR) &&
           (permitted == CAP_CLEAR) && (inheritable == CAP_CLEAR)) {
             /* 'bounding' doesn't matter */
            continue;
        }

        str = talloc_asprintf_append(str,
            "   %25s: effective = %s, permitted = %s, inheritable = %s, bounding = %s\n",
            _all_caps[i].name, cap_flag_to_str(effective),
            cap_flag_to_str(permitted), cap_flag_to_str(inheritable),
            cap_flag_to_str(bounding));
        if (str == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = 0;

done:
    if (ret == 0) {
        *_str = str;
    } else {
        talloc_free(str);
    }

    if (cap_free(caps) == -1) {
        DEBUG(SSSDBG_TRACE_FUNC, "cap_free() failed\n");
    }

    return ret;
}

errno_t sss_drop_cap(cap_value_t cap)
{
    if (!CAP_IS_SUPPORTED(cap)) {
        return EINVAL;
    }

    int ret;

    cap_t caps = cap_get_proc();
    if (caps == NULL) {
        ret = errno;
        DEBUG(SSSDBG_TRACE_FUNC, "cap_get_proc() failed: %d ('%s')\n",
              ret, strerror(ret));
        return ret;
    }
    if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap, CAP_CLEAR) == -1) {
        ret = errno;
        DEBUG(SSSDBG_TRACE_FUNC,
              "cap_set_flag(CAP_EFFECTIVE) failed: %d ('%s')\n",
              ret, strerror(ret));
        goto done;
    }
    if (cap_set_flag(caps, CAP_PERMITTED, 1, &cap, CAP_CLEAR) == -1) {
        ret = errno;
        DEBUG(SSSDBG_TRACE_FUNC,
              "cap_set_flag(CAP_PERMITTED) failed: %d ('%s')\n",
              ret, strerror(ret));
        goto done;
    }
    if (cap_set_flag(caps, CAP_INHERITABLE, 1, &cap, CAP_CLEAR) == -1) {
        ret = errno;
        DEBUG(SSSDBG_TRACE_FUNC,
              "cap_set_flag(CAP_INHERITABLE) failed: %d ('%s')\n",
              ret, strerror(ret));
        goto done;
    }
    if (cap_set_proc(caps) == -1) {
        ret = errno;
        DEBUG(SSSDBG_TRACE_FUNC, "cap_set_proc() failed: %d ('%s')\n",
              ret, strerror(ret));
        goto done;
    }

    ret = 0;

done:
    if (cap_free(caps) == -1) {
        DEBUG(SSSDBG_TRACE_FUNC, "cap_free() failed\n");
    }

    return ret;
}

errno_t sss_set_cap_effective(cap_value_t cap, bool effective)
{
    if (!CAP_IS_SUPPORTED(cap)) {
        return EINVAL;
    }

    int ret;
    cap_flag_value_t value = (effective ? CAP_SET : CAP_CLEAR);

    cap_t caps = cap_get_proc();
    if (caps == NULL) {
        ret = errno;
        DEBUG(SSSDBG_TRACE_FUNC, "cap_get_proc() failed: %d ('%s')\n",
              ret, strerror(ret));
        return ret;
    }
    if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap, value) == -1) {
        ret = errno;
        DEBUG(SSSDBG_TRACE_FUNC,
              "cap_set_flag(CAP_EFFECTIVE) failed: %d ('%s')\n",
              ret, strerror(ret));
        goto done;
    }
    if (cap_set_proc(caps) == -1) {
        ret = errno;
        DEBUG(SSSDBG_TRACE_FUNC, "cap_set_proc() failed: %d ('%s')\n",
              ret, strerror(ret));
        goto done;
    }

    ret = 0;

done:
    if (cap_free(caps) == -1) {
        DEBUG(SSSDBG_TRACE_FUNC, "cap_free() failed\n");
    }

    return ret;
}

void sss_drop_all_caps(void)
{
    int ret;

    cap_t caps = cap_get_proc();
    if (caps == NULL) {
        ret = errno;
        DEBUG(SSSDBG_TRACE_FUNC, "cap_get_proc() failed: %d ('%s')\n",
              ret, strerror(ret));
        return;
    }
    if (cap_clear(caps) == -1) {
        ret = errno;
        DEBUG(SSSDBG_TRACE_FUNC,
              "cap_clear() failed: %d ('%s')\n", ret, strerror(ret));
        goto done;
    }
    if (cap_set_proc(caps) == -1) {
        ret = errno;
        DEBUG(SSSDBG_TRACE_FUNC, "cap_set_proc() failed: %d ('%s')\n",
              ret, strerror(ret));
        goto done;
    }

done:
    if (cap_free(caps) == -1) {
        DEBUG(SSSDBG_TRACE_FUNC, "cap_free() failed\n");
    }
}


void sss_log_process_caps(const char *stage)
{
    errno_t ret;
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    char *caps = NULL;

    getresuid(&ruid, &euid, &suid);
    getresgid(&rgid, &egid, &sgid);

    DEBUG(SSSDBG_CONF_SETTINGS,
         "%s under ruid=%"SPRIuid", euid=%"SPRIuid", suid=%"SPRIuid" : "
                  "rgid=%"SPRIgid", egid=%"SPRIgid", sgid=%"SPRIgid"\n",
         stage, ruid, euid, suid, rgid, egid, sgid);

    ret = sss_log_caps_to_str(true, &caps);
    if (ret == 0) {
        DEBUG(SSSDBG_CONF_SETTINGS, "With following capabilities:\n%s",
              caps ? caps : "   (nothing)\n");
        talloc_free(caps);
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE, "Failed to get current capabilities\n");
    }
}

#else // __linux__

errno_t sss_log_caps_to_str(bool only_non_zero, char **_str)
{
    *_str = NULL;
    return 0;
}

errno_t sss_set_cap_effective(cap_value_t cap, bool effective)
{
    return 0;
}

errno_t sss_drop_cap(cap_value_t cap)
{
    return 0;
}

void sss_drop_all_caps(void)
{
}

void sss_log_process_caps(const char *stage)
{
}

#endif
