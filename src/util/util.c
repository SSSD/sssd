/*
    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2009 Red Hat

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

#include <ctype.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <talloc.h>
#include <dhash.h>

#include "util/util.h"
#include "util/sss_utf8.h"

int split_on_separator(TALLOC_CTX *mem_ctx, const char *str,
                       const char sep, bool trim, bool skip_empty,
                       char ***_list, int *size)
{
    int ret;
    const char *substr_end = str;
    const char *substr_begin = str;
    const char *sep_pos = NULL;
    size_t substr_len;
    char **list = NULL;
    int num_strings = 0;
    TALLOC_CTX *tmp_ctx = NULL;

    if (str == NULL || *str == '\0' || _list == NULL) {
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    do {
        substr_len = 0;

        /* If this is not the first substring, then move from the separator. */
        if (sep_pos != NULL) {
            substr_end = sep_pos + 1;
            substr_begin = sep_pos + 1;
        }

        /* Find end of the first substring */
        while (*substr_end != sep && *substr_end != '\0') {
            substr_end++;
            substr_len++;
        }

        sep_pos = substr_end;

        if (trim) {
            /* Trim leading whitespace */
            while (isspace(*substr_begin) && substr_begin < substr_end) {
                substr_begin++;
                substr_len--;
            }

            /* Trim trailing whitespace */
            while (substr_end - 1 > substr_begin && isspace(*(substr_end-1))) {
                substr_end--;
                substr_len--;
            }
        }

        /* Copy the substring to the output list of strings */
        if (skip_empty == false || substr_len > 0) {
            list = talloc_realloc(tmp_ctx, list, char*, num_strings + 2);
            if (list == NULL) {
                ret = ENOMEM;
                goto done;
            }

            /* empty string is stored for substr_len == 0 */
            list[num_strings] = talloc_strndup(list, substr_begin, substr_len);
            if (list[num_strings] == NULL) {
                ret = ENOMEM;
                goto done;
            }
            num_strings++;
        }

    } while (*sep_pos != '\0');

    if (list == NULL) {
        /* No allocations were done, make space for the NULL */
        list = talloc(tmp_ctx, char *);
        if (list == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }
    list[num_strings] = NULL;

    if (size) {
        *size = num_strings;
    }

    *_list = talloc_steal(mem_ctx, list);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static void free_args(char **args)
{
    int i;

    if (args) {
        for (i = 0; args[i]; i++) free(args[i]);
        free(args);
    }
}

/* parse a string into arguments.
 * arguments are separated by a space
 * '\' is an escape character and can be used only to escape
 * itself or the white space.
 */
char **parse_args(const char *str)
{
    const char *p;
    char **ret, **r;
    char *tmp;
    int num;
    int i;
    bool e, w;

    tmp = malloc(strlen(str) + 1);
    if (!tmp) return NULL;

    ret = NULL;
    num = 0;
    i = 0;
    e = false;
    /* skip leading whitespaces */
    w = true;
    p = str;
    while (*p) {
        if (*p == '\\') {
            w = false;
            if (e) {
                /* if we were already escaping, add a '\' literal */
                tmp[i] = '\\';
                i++;
                e = false;
            } else {
                /* otherwise just start escaping */
                e = true;
            }
        } else if (isspace(*p)) {
            if (e) {
                /* Add escaped whitespace literally */
                tmp[i] = *p;
                i++;
                e = false;
            } else if (w == false) {
                /* If previous character was non-whitespace, arg break */
                tmp[i] = '\0';
                i++;
                w = true;
            }
            /* previous char was whitespace as well, skip it */
        } else {
            w = false;
            if (e) {
                /* Prepend escaped chars with a literal \ */
                tmp[i] = '\\';
                i++;
                e = false;
            }
            /* Copy character from the source string */
            tmp[i] = *p;
            i++;
        }

        p++;

        /* check if this was the last char */
        if (*p == '\0') {
            if (e) {
                tmp[i] = '\\';
                i++;
                e = false;
            }
            tmp[i] = '\0';
            i++;
        }

        /* save token to result array */
        if (i > 1 && tmp[i-1] == '\0') {
            r = realloc(ret, (num + 2) * sizeof(char *));
            if (!r) goto fail;
            ret = r;
            ret[num+1] = NULL;
            ret[num] = strdup(tmp);
            if (!ret[num]) goto fail;
            num++;
            i = 0;
        }
    }

    free(tmp);
    return ret;

fail:
    free(tmp);
    free_args(ret);
    return NULL;
}

char **dup_string_list(TALLOC_CTX *memctx, const char **str_list)
{
    int i = 0;
    int j = 0;
    char **dup_list;

    if (!str_list) {
        return NULL;
    }

    /* Find the size of the list */
    while (str_list[i]) i++;

    dup_list = talloc_array(memctx, char *, i+1);
    if (!dup_list) {
        return NULL;
    }

    /* Copy the elements */
    for (j = 0; j < i; j++) {
        dup_list[j] = talloc_strdup(dup_list, str_list[j]);
        if (!dup_list[j]) {
            talloc_free(dup_list);
            return NULL;
        }
    }

    /* NULL-terminate the list */
    dup_list[i] = NULL;

    return dup_list;
}

/* Take two string lists (terminated on a NULL char*)
 * and return up to three arrays of strings based on
 * shared ownership.
 *
 * Pass NULL to any return type you don't care about
 */
errno_t diff_string_lists(TALLOC_CTX *memctx,
                          char **_list1,
                          char **_list2,
                          char ***_list1_only,
                          char ***_list2_only,
                          char ***_both_lists)
{
    int error;
    errno_t ret;
    int i;
    int i2 = 0;
    int i12 = 0;
    hash_table_t *table;
    hash_key_t key;
    hash_value_t value;
    char **list1 = NULL;
    char **list2 = NULL;
    char **list1_only = NULL;
    char **list2_only = NULL;
    char **both_lists = NULL;
    unsigned long count;
    hash_key_t *keys;

    TALLOC_CTX *tmp_ctx = talloc_new(memctx);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    if (!_list1) {
        list1 = talloc_array(tmp_ctx, char *, 1);
        if (!list1) {
            talloc_free(tmp_ctx);
            return ENOMEM;
        }
        list1[0] = NULL;
    }
    else {
        list1 = _list1;
    }

    if (!_list2) {
        list2 = talloc_array(tmp_ctx, char *, 1);
        if (!list2) {
            talloc_free(tmp_ctx);
            return ENOMEM;
        }
        list2[0] = NULL;
    }
    else {
        list2 = _list2;
    }

    error = hash_create(10, &table, NULL, NULL);
    if (error != HASH_SUCCESS) {
        talloc_free(tmp_ctx);
        return EIO;
    }

    key.type = HASH_KEY_STRING;
    value.type = HASH_VALUE_UNDEF;

    /* Add all entries from list 1 into a hash table */
    i = 0;
    while (list1[i]) {
        key.str = talloc_strdup(tmp_ctx, list1[i]);
        error = hash_enter(table, &key, &value);
        if (error != HASH_SUCCESS) {
            ret = EIO;
            goto done;
        }
        i++;
    }

    /* Iterate through list 2 and remove matching items */
    i = 0;
    while (list2[i]) {
        key.str = talloc_strdup(tmp_ctx, list2[i]);
        error = hash_delete(table, &key);
        if (error == HASH_SUCCESS) {
            if (_both_lists) {
                /* String was present in both lists */
                i12++;
                both_lists = talloc_realloc(tmp_ctx, both_lists, char *, i12+1);
                if (!both_lists) {
                    ret = ENOMEM;
                    goto done;
                }
                both_lists[i12-1] = talloc_strdup(both_lists, list2[i]);
                if (!both_lists[i12-1]) {
                    ret = ENOMEM;
                    goto done;
                }

                both_lists[i12] = NULL;
            }
        }
        else if (error == HASH_ERROR_KEY_NOT_FOUND) {
            if (_list2_only) {
                /* String was present only in list2 */
                i2++;
                list2_only = talloc_realloc(tmp_ctx, list2_only,
                                            char *, i2+1);
                if (!list2_only) {
                    ret = ENOMEM;
                    goto done;
                }
                list2_only[i2-1] = talloc_strdup(list2_only, list2[i]);
                if (!list2_only[i2-1]) {
                    ret = ENOMEM;
                    goto done;
                }

                list2_only[i2] = NULL;
            }
        }
        else {
            /* An error occurred */
            ret = EIO;
            goto done;
        }
        i++;
    }

    /* Get the leftover entries in the hash table */
    if (_list1_only) {
        error = hash_keys(table, &count, &keys);
        if (error != HASH_SUCCESS) {
            ret = EIO;
            goto done;
        }

        list1_only = talloc_array(tmp_ctx, char *, count+1);
        if (!list1_only) {
            ret = ENOMEM;
            goto done;
        }

        for (i = 0; i < count; i++) {
            list1_only[i] = talloc_strdup(list1_only, keys[i].str);
            if (!list1_only[i]) {
                ret = ENOMEM;
                goto done;
            }
        }
        list1_only[count] = NULL;

        free(keys);

        *_list1_only = talloc_steal(memctx, list1_only);
    }

    if (_list2_only) {
        if (list2_only) {
            *_list2_only = talloc_steal(memctx, list2_only);
        }
        else {
            *_list2_only = talloc_array(memctx, char *, 1);
            if (!(*_list2_only)) {
                ret = ENOMEM;
                goto done;
            }
            *_list2_only[0] = NULL;
        }
    }

    if (_both_lists) {
        if (both_lists) {
            *_both_lists = talloc_steal(memctx, both_lists);
        }
        else {
            *_both_lists = talloc_array(memctx, char *, 1);
            if (!(*_both_lists)) {
                ret = ENOMEM;
                goto done;
            }
            *_both_lists[0] = NULL;
        }
    }

    ret = EOK;

done:
    hash_destroy(table);
    talloc_free(tmp_ctx);
    return ret;
}

static void *hash_talloc(const size_t size, void *pvt)
{
    return talloc_size(pvt, size);
}

static void hash_talloc_free(void *ptr, void *pvt)
{
    talloc_free(ptr);
}

errno_t sss_hash_create_ex(TALLOC_CTX *mem_ctx,
                           unsigned long count,
                           hash_table_t **tbl,
                           unsigned int directory_bits,
                           unsigned int segment_bits,
                           unsigned long min_load_factor,
                           unsigned long max_load_factor,
                           hash_delete_callback *delete_callback,
                           void *delete_private_data)
{
    errno_t ret;
    hash_table_t *table;
    int hret;

    TALLOC_CTX *internal_ctx;
    internal_ctx = talloc_new(NULL);
    if (!internal_ctx) {
        return ENOMEM;
    }

    hret = hash_create_ex(count, &table, directory_bits, segment_bits,
                          min_load_factor, max_load_factor,
                          hash_talloc, hash_talloc_free, internal_ctx,
                          delete_callback, delete_private_data);
    switch (hret) {
    case HASH_SUCCESS:
        /* Steal the table pointer onto the mem_ctx,
         * then make the internal_ctx a child of
         * table.
         *
         * This way, we can clean up the values when
         * we talloc_free() the table
         */
        *tbl = talloc_steal(mem_ctx, table);
        talloc_steal(table, internal_ctx);
        return EOK;

    case HASH_ERROR_NO_MEMORY:
        ret = ENOMEM;
        break;
    default:
        ret = EIO;
    }

    DEBUG(SSSDBG_FATAL_FAILURE, "Could not create hash table: [%d][%s]\n",
              hret, hash_error_string(hret));

    talloc_free(internal_ctx);
    return ret;
}

errno_t sss_hash_create(TALLOC_CTX *mem_ctx, unsigned long count,
                        hash_table_t **tbl)
{
    return sss_hash_create_ex(mem_ctx, count, tbl, 0, 0, 0, 0, NULL, NULL);
}

errno_t sss_filter_sanitize(TALLOC_CTX *mem_ctx,
                            const char *input,
                            char **sanitized)
{
    char *output;
    size_t i = 0;
    size_t j = 0;

    /* Assume the worst-case. We'll resize it later, once */
    output = talloc_array(mem_ctx, char, strlen(input) * 3 + 1);
    if (!output) {
        return ENOMEM;
    }

    while (input[i]) {
        switch(input[i]) {
        case '\t':
            output[j++] = '\\';
            output[j++] = '0';
            output[j++] = '9';
            break;
        case ' ':
            output[j++] = '\\';
            output[j++] = '2';
            output[j++] = '0';
            break;
        case '*':
            output[j++] = '\\';
            output[j++] = '2';
            output[j++] = 'a';
            break;
        case '(':
            output[j++] = '\\';
            output[j++] = '2';
            output[j++] = '8';
            break;
        case ')':
            output[j++] = '\\';
            output[j++] = '2';
            output[j++] = '9';
            break;
        case '\\':
            output[j++] = '\\';
            output[j++] = '5';
            output[j++] = 'c';
            break;
        default:
            output[j++] = input[i];
        }

        i++;
    }
    output[j] = '\0';
    *sanitized = talloc_realloc(mem_ctx, output, char, j+1);
    if (!*sanitized) {
        talloc_free(output);
        return ENOMEM;
    }

    return EOK;
}

char *
sss_escape_ip_address(TALLOC_CTX *mem_ctx, int family, const char *addr)
{
    return family == AF_INET6 ? talloc_asprintf(mem_ctx, "[%s]", addr) :
                                talloc_strdup(mem_ctx, addr);
}

/* out->len includes terminating '\0' */
void to_sized_string(struct sized_string *out, const char *in)
{
    out->str = in;
    if (out->str) {
        out->len = strlen(out->str) + 1;
    } else {
        out->len = 0;
    }
}

/* This function only removes first and last
 * character if the first character was '['.
 *
 * NOTE: This means, that ipv6addr must NOT be followed
 * by port number.
 */
errno_t
remove_ipv6_brackets(char *ipv6addr)
{
    size_t len;

    if (ipv6addr && ipv6addr[0] == '[') {
        len = strlen(ipv6addr);
        if (len < 3) {
            return EINVAL;
        }

        memmove(ipv6addr, &ipv6addr[1], len - 2);
        ipv6addr[len -2] = '\0';
    }

    return EOK;
}

errno_t add_string_to_list(TALLOC_CTX *mem_ctx, const char *string,
                           char ***list_p)
{
    size_t c;
    char **old_list = NULL;
    char **new_list = NULL;

    if (string == NULL || list_p == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing string or list.\n");
        return EINVAL;
    }

    old_list = *list_p;

    if (old_list == NULL) {
        /* If the input is a NULL list a new one is created with the new
         * string and the terminating NULL element. */
        c = 0;
        new_list = talloc_array(mem_ctx, char *, 2);
    } else {
        for (c = 0; old_list[c] != NULL; c++);
        /* Allocate one extra space for the new service and one for
         * the terminating NULL
         */
        new_list = talloc_realloc(mem_ctx, old_list, char *, c + 2);
    }

    if (new_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array/talloc_realloc failed.\n");
        return ENOMEM;
    }

    new_list[c] = talloc_strdup(new_list, string);
    if (new_list[c] == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        talloc_free(new_list);
        return ENOMEM;
    }

    new_list[c + 1] = NULL;

    *list_p = new_list;

    return EOK;
}

bool string_in_list(const char *string, char **list, bool case_sensitive)
{
    size_t c;
    int(*compare)(const char *s1, const char *s2);

    if (string == NULL || list == NULL || *list == NULL) {
        return false;
    }

    compare = case_sensitive ? strcmp : strcasecmp;

    for (c = 0; list[c] != NULL; c++) {
        if (compare(string, list[c]) == 0) {
            return true;
        }
    }

    return false;
}

void safezero(void *data, size_t size)
{
    volatile uint8_t *p = data;

    while (size--) {
        *p++ = 0;
    }
}

int domain_to_basedn(TALLOC_CTX *memctx, const char *domain, char **basedn)
{
    const char *s;
    char *dn;
    char *p;
    int l;

    if (!domain || !basedn) {
        return EINVAL;
    }

    s = domain;
    dn = talloc_strdup(memctx, "dc=");

    while ((p = strchr(s, '.'))) {
        l = p - s;
        dn = talloc_asprintf_append_buffer(dn, "%.*s,dc=", l, s);
        if (!dn) {
            return ENOMEM;
        }
        s = p + 1;
    }
    dn = talloc_strdup_append_buffer(dn, s);
    if (!dn) {
        return ENOMEM;
    }

    for (p=dn; *p; ++p) {
        *p = tolower(*p);
    }

    *basedn = dn;
    return EOK;
}

bool is_host_in_domain(const char *host, const char *domain)
{
    int diff = strlen(host) - strlen(domain);

    if (diff == 0 && strcmp(host, domain) == 0) {
        return true;
    }

    if (diff > 0 && strcmp(host + diff, domain) == 0 && host[diff - 1] == '.') {
        return true;
    }

    return false;
}

/* addr is in network order for both IPv4 and IPv6 versions */
bool check_ipv4_addr(struct in_addr *addr, uint8_t flags)
{
    char straddr[INET_ADDRSTRLEN];

    if (inet_ntop(AF_INET, addr, straddr, INET_ADDRSTRLEN) == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "inet_ntop failed, won't log IP addresses\n");
        snprintf(straddr, INET_ADDRSTRLEN, "unknown");
    }

    if ((flags & SSS_NO_MULTICAST) && IN_MULTICAST(ntohl(addr->s_addr))) {
        DEBUG(SSSDBG_FUNC_DATA, "Multicast IPv4 address %s\n", straddr);
        return false;
    } else if ((flags & SSS_NO_LOOPBACK)
               && inet_netof(*addr) == IN_LOOPBACKNET) {
        DEBUG(SSSDBG_FUNC_DATA, "Loopback IPv4 address %s\n", straddr);
        return false;
    } else if ((flags & SSS_NO_LINKLOCAL)
               && (addr->s_addr & htonl(0xffff0000)) == htonl(0xa9fe0000)) {
        /* 169.254.0.0/16 */
        DEBUG(SSSDBG_FUNC_DATA, "Link-local IPv4 address %s\n", straddr);
        return false;
    } else if ((flags & SSS_NO_BROADCAST)
               && addr->s_addr == htonl(INADDR_BROADCAST)) {
        DEBUG(SSSDBG_FUNC_DATA, "Broadcast IPv4 address %s\n", straddr);
        return false;
    }

    return true;
}

bool check_ipv6_addr(struct in6_addr *addr, uint8_t flags)
{
    char straddr[INET6_ADDRSTRLEN];

    if (inet_ntop(AF_INET6, addr, straddr, INET6_ADDRSTRLEN) == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "inet_ntop failed, won't log IP addresses\n");
        snprintf(straddr, INET6_ADDRSTRLEN, "unknown");
    }

    if ((flags & SSS_NO_LINKLOCAL) && IN6_IS_ADDR_LINKLOCAL(addr)) {
        DEBUG(SSSDBG_FUNC_DATA, "Link local IPv6 address %s\n", straddr);
        return false;
    } else if ((flags & SSS_NO_LOOPBACK) && IN6_IS_ADDR_LOOPBACK(addr)) {
        DEBUG(SSSDBG_FUNC_DATA, "Loopback IPv6 address %s\n", straddr);
        return false;
    } else if ((flags & SSS_NO_MULTICAST) && IN6_IS_ADDR_MULTICAST(addr)) {
        DEBUG(SSSDBG_FUNC_DATA, "Multicast IPv6 address %s\n", straddr);
        return false;
    }

    return true;
}

const char * const * get_known_services(void)
{
    static const char *svc[] = {"nss", "pam", "sudo", "autofs",
                                "ssh", "pac", "ifp", NULL };

    return svc;
}
