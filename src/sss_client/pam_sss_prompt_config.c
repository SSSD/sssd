/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2019 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "config.h"
#include <stdlib.h>
#include <errno.h>

#include "sss_cli.h"

#include <libintl.h>
#define _(STRING) dgettext (PACKAGE, STRING)

struct prompt_config_password {
    char *prompt;
};

struct prompt_config_2fa {
    char *prompt_1st;
    char *prompt_2nd;
};

struct prompt_config_2fa_single {
    char *prompt;
};

struct prompt_config_sc_pin {
    char *prompt; /* Currently not used */
};

struct prompt_config {
    enum prompt_config_type type;
    union {
        struct prompt_config_password password;
        struct prompt_config_2fa two_fa;
        struct prompt_config_2fa_single two_fa_single;
        struct prompt_config_sc_pin sc_pin;
    } data;
};

enum prompt_config_type pc_get_type(struct prompt_config *pc)
{
    if (pc != NULL && pc->type > PC_TYPE_INVALID && pc->type < PC_TYPE_LAST) {
        return pc->type;
    }
    return PC_TYPE_INVALID;
}

const char *pc_get_password_prompt(struct prompt_config *pc)
{
    if (pc != NULL && pc_get_type(pc) == PC_TYPE_PASSWORD) {
        return pc->data.password.prompt;
    }
    return NULL;
}

const char *pc_get_2fa_1st_prompt(struct prompt_config *pc)
{
    if (pc != NULL && pc_get_type(pc) == PC_TYPE_2FA) {
        return pc->data.two_fa.prompt_1st;
    }
    return NULL;
}

const char *pc_get_2fa_2nd_prompt(struct prompt_config *pc)
{
    if (pc != NULL && pc_get_type(pc) == PC_TYPE_2FA) {
        return pc->data.two_fa.prompt_2nd;
    }
    return NULL;
}

const char *pc_get_2fa_single_prompt(struct prompt_config *pc)
{
    if (pc != NULL && pc_get_type(pc) == PC_TYPE_2FA_SINGLE) {
        return pc->data.two_fa_single.prompt;
    }
    return NULL;
}

static void pc_free_password(struct prompt_config *pc)
{
    if (pc != NULL && pc_get_type(pc) == PC_TYPE_PASSWORD) {
        free(pc->data.password.prompt);
    }
    return;
}

static void pc_free_2fa(struct prompt_config *pc)
{
    if (pc != NULL && pc_get_type(pc) == PC_TYPE_2FA) {
        free(pc->data.two_fa.prompt_1st);
        free(pc->data.two_fa.prompt_2nd);
    }
    return;
}

static void pc_free_2fa_single(struct prompt_config *pc)
{
    if (pc != NULL && pc_get_type(pc) == PC_TYPE_2FA_SINGLE) {
        free(pc->data.two_fa_single.prompt);
    }
    return;
}

static void pc_free_sc_pin(struct prompt_config *pc)
{
    if (pc != NULL && pc_get_type(pc) == PC_TYPE_SC_PIN) {
        free(pc->data.sc_pin.prompt);
    }
    return;
}

void pc_list_free(struct prompt_config **pc_list)
{
    size_t c;

    if (pc_list == NULL) {
        return;
    }

    for (c = 0; pc_list[c] != NULL; c++) {
        switch (pc_list[c]->type) {
        case PC_TYPE_PASSWORD:
            pc_free_password(pc_list[c]);
            break;
        case PC_TYPE_2FA:
            pc_free_2fa(pc_list[c]);
            break;
        case PC_TYPE_2FA_SINGLE:
            pc_free_2fa_single(pc_list[c]);
            break;
        case PC_TYPE_SC_PIN:
            pc_free_sc_pin(pc_list[c]);
            break;
        default:
            return;
        }
        free(pc_list[c]);
    }
    free(pc_list);
}

static errno_t pc_list_add_pc(struct prompt_config ***pc_list,
                              struct prompt_config *pc)
{
    size_t c = 0;
    struct prompt_config **pcl;

    for (c = 0; *pc_list != NULL && (*pc_list)[c] != NULL; c++); /* just counting */

    pcl = realloc(*pc_list, (c + 2) * sizeof(struct prompt_config *));
    if (pcl == NULL) {
        return ENOMEM;
    }
    pcl[c] = pc;
    pcl[c + 1] = NULL;

    *pc_list = pcl;

    return EOK;
}

#define DEFAULT_PASSWORD_PROMPT _("Password: ")
#define DEFAULT_2FA_SINGLE_PROMPT _("Password + Token value: ")
#define DEFAULT_2FA_PROMPT_1ST _("First Factor: ")
#define DEFAULT_2FA_PROMPT_2ND _("Second Factor: ")

errno_t pc_list_add_password(struct prompt_config ***pc_list,
                             const char *prompt)
{
    struct prompt_config *pc;
    int ret;

    if (pc_list == NULL) {
        return EINVAL;
    }

    pc = calloc(1, sizeof(struct prompt_config));
    if (pc == NULL) {
        return ENOMEM;
    }

    pc->type = PC_TYPE_PASSWORD;
    pc->data.password.prompt = strdup(prompt != NULL ? prompt
                                                     : DEFAULT_PASSWORD_PROMPT);
    if (pc->data.password.prompt == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = pc_list_add_pc(pc_list, pc);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        free(pc->data.password.prompt);
        free(pc);
    }

    return ret;
}

errno_t pc_list_add_2fa(struct prompt_config ***pc_list,
                        const char *prompt_1st, const char *prompt_2nd)
{
    struct prompt_config *pc;
    int ret;

    if (pc_list == NULL) {
        return EINVAL;
    }

    pc = calloc(1, sizeof(struct prompt_config));
    if (pc == NULL) {
        return ENOMEM;
    }

    pc->type = PC_TYPE_2FA;
    pc->data.two_fa.prompt_1st = strdup(prompt_1st != NULL ? prompt_1st
                                                   : DEFAULT_2FA_PROMPT_1ST);
    if (pc->data.two_fa.prompt_1st == NULL) {
        ret = ENOMEM;
        goto done;
    }
    pc->data.two_fa.prompt_2nd = strdup(prompt_2nd != NULL ? prompt_2nd
                                                   : DEFAULT_2FA_PROMPT_2ND);
    if (pc->data.two_fa.prompt_2nd == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = pc_list_add_pc(pc_list, pc);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        free(pc->data.two_fa.prompt_1st);
        free(pc->data.two_fa.prompt_2nd);
        free(pc);
    }

    return ret;
}

errno_t pc_list_add_2fa_single(struct prompt_config ***pc_list,
                               const char *prompt)
{
    struct prompt_config *pc;
    int ret;

    if (pc_list == NULL) {
        return EINVAL;
    }

    pc = calloc(1, sizeof(struct prompt_config));
    if (pc == NULL) {
        return ENOMEM;
    }

    pc->type = PC_TYPE_2FA_SINGLE;
    pc->data.two_fa_single.prompt = strdup(prompt != NULL ? prompt
                                                   : DEFAULT_2FA_SINGLE_PROMPT);
    if (pc->data.two_fa_single.prompt == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = pc_list_add_pc(pc_list, pc);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        free(pc->data.two_fa_single.prompt);
        free(pc);
    }

    return ret;
}

errno_t pam_get_response_prompt_config(struct prompt_config **pc_list, int *len,
                                       uint8_t **data)
{
    size_t c;
    size_t l = 0;
    uint8_t *d = NULL;
    uint32_t uint32_val;
    size_t rp;

    if (pc_list == NULL || *pc_list == NULL) {
        return ENOENT;
    }

    l += sizeof(uint32_t);
    for (c = 0; pc_list[c] != NULL; c++) {
        l += sizeof(uint32_t);
        switch (pc_list[c]->type) {
        case PC_TYPE_PASSWORD:
            l += sizeof(uint32_t);
            l += strlen(pc_list[c]->data.password.prompt);
            break;
        case PC_TYPE_2FA:
            l += sizeof(uint32_t);
            l += strlen(pc_list[c]->data.two_fa.prompt_1st);
            l += sizeof(uint32_t);
            l += strlen(pc_list[c]->data.two_fa.prompt_2nd);
            break;
        case PC_TYPE_2FA_SINGLE:
            l += sizeof(uint32_t);
            l += strlen(pc_list[c]->data.two_fa_single.prompt);
            break;
        case PC_TYPE_SC_PIN:
            break;
        default:
            return EINVAL;
        }
    }

    d = malloc(l * sizeof(uint8_t));
    if (d == NULL) {
        return ENOMEM;
    }

    rp = 0;
    uint32_val = c;
    SAFEALIGN_COPY_UINT32(&d[rp], &uint32_val, &rp);

    for (c = 0; pc_list[c] != NULL; c++) {
        uint32_val = pc_list[c]->type;
        SAFEALIGN_COPY_UINT32(&d[rp], &uint32_val, &rp);

        switch (pc_list[c]->type) {
        case PC_TYPE_PASSWORD:
            SAFEALIGN_SET_UINT32(&d[rp],
                                 strlen(pc_list[c]->data.password.prompt), &rp);
            safealign_memcpy(&d[rp], pc_list[c]->data.password.prompt,
                             strlen(pc_list[c]->data.password.prompt), &rp);
            break;
        case PC_TYPE_2FA:
            SAFEALIGN_SET_UINT32(&d[rp],
                                 strlen(pc_list[c]->data.two_fa.prompt_1st),
                                 &rp);
            safealign_memcpy(&d[rp], pc_list[c]->data.two_fa.prompt_1st,
                             strlen(pc_list[c]->data.two_fa.prompt_1st), &rp);
            SAFEALIGN_SET_UINT32(&d[rp],
                                 strlen(pc_list[c]->data.two_fa.prompt_2nd),
                                 &rp);
            safealign_memcpy(&d[rp], pc_list[c]->data.two_fa.prompt_2nd,
                             strlen(pc_list[c]->data.two_fa.prompt_2nd), &rp);
            break;
        case PC_TYPE_2FA_SINGLE:
            SAFEALIGN_SET_UINT32(&d[rp],
                                 strlen(pc_list[c]->data.two_fa_single.prompt),
                                 &rp);
            safealign_memcpy(&d[rp], pc_list[c]->data.two_fa_single.prompt,
                             strlen(pc_list[c]->data.two_fa_single.prompt),
                             &rp);
            break;
        case PC_TYPE_SC_PIN:
            break;
        default:
            free(d);
            return EINVAL;
        }
    }

    if (rp != l) {
        free(d);
        return EFAULT;
    }

    *data = d;
    *len = l;

    return EOK;
}

errno_t pc_list_from_response(int size, uint8_t *buf,
                              struct prompt_config ***pc_list)
{
    int ret;
    uint32_t count;
    uint32_t type;
    uint32_t l;
    size_t rp;
    size_t c;
    struct prompt_config **pl = NULL;
    char *str;
    char *str2;

    if (buf == NULL || size < 3 * sizeof(uint32_t)) {
        return EINVAL;
    }

    rp = 0;
    SAFEALIGN_COPY_UINT32_CHECK(&count, buf + rp, size, &rp);

    for (c = 0; c < count; c++) {
        /* Since we already know size < 3 * sizeof(uint32_t) this check should
         * be safe and without over- or underflow. */
        if (rp > size - sizeof(uint32_t)) {
            ret = EINVAL;
            goto done;
        }
        SAFEALIGN_COPY_UINT32(&type, buf + rp, &rp);

        switch (type) {
        case PC_TYPE_PASSWORD:
            if (rp > size - sizeof(uint32_t)) {
                ret = EINVAL;
                goto done;
            }
            SAFEALIGN_COPY_UINT32(&l, buf + rp, &rp);

            if (l > size || rp > size - l) {
                ret = EINVAL;
                goto done;
            }
            str = strndup((char *) buf + rp, l);
            if (str == NULL) {
                ret = ENOMEM;
                goto done;
            }
            rp += l;

            ret = pc_list_add_password(&pl, str);
            free(str);
            if (ret != EOK) {
                goto done;
            }
            break;
        case PC_TYPE_2FA:
            if (rp > size - sizeof(uint32_t)) {
                ret = EINVAL;
                goto done;
            }
            SAFEALIGN_COPY_UINT32(&l, buf + rp, &rp);

            if (l > size || rp > size - l) {
                ret = EINVAL;
                goto done;
            }
            str = strndup((char *) buf + rp, l);
            if (str == NULL) {
                ret = ENOMEM;
                goto done;
            }
            rp += l;

            if (rp > size - sizeof(uint32_t)) {
                free(str);
                ret = EINVAL;
                goto done;
            }
            SAFEALIGN_COPY_UINT32(&l, buf + rp, &rp);

            if (l > size || rp > size - l) {
                free(str);
                ret = EINVAL;
                goto done;
            }
            str2 = strndup((char *) buf + rp, l);
            if (str2 == NULL) {
                free(str);
                ret = ENOMEM;
                goto done;
            }
            rp += l;

            ret = pc_list_add_2fa(&pl, str, str2);
            free(str);
            free(str2);
            if (ret != EOK) {
                goto done;
            }
            break;
        case PC_TYPE_2FA_SINGLE:
            if (rp > size - sizeof(uint32_t)) {
                ret = EINVAL;
                goto done;
            }
            SAFEALIGN_COPY_UINT32(&l, buf + rp, &rp);

            if (l > size || rp > size - l) {
                ret = EINVAL;
                goto done;
            }
            str = strndup((char *) buf + rp, l);
            if (str == NULL) {
                ret = ENOMEM;
                goto done;
            }
            rp += l;

            ret = pc_list_add_2fa_single(&pl, str);
            free(str);
            if (ret != EOK) {
                goto done;
            }
            break;
        case PC_TYPE_SC_PIN:
            break;
        default:
            ret = EINVAL;
            goto done;
        }
    }

    *pc_list = pl;

    ret = EOK;

done:
    if (ret != EOK) {
        pc_list_free(pl);
    }

    return ret;
}
