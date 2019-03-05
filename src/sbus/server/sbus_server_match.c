/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2017 Red Hat

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

#include <errno.h>
#include <string.h>
#include <tevent.h>
#include <talloc.h>

#include "util/util.h"
#include "util/sss_ptr_hash.h"
#include "util/sss_ptr_list.h"
#include "sbus/sbus_private.h"

struct sbus_rule {
    const char *type;
    const char *interface;
    const char *member;
};

static struct sbus_connection *
sbus_match_find(struct sss_ptr_list *list,
                struct sbus_connection *conn)
{
    struct sbus_connection *match_conn;

    SSS_PTR_LIST_FOR_EACH(list, match_conn, struct sbus_connection) {
        if (match_conn == conn) {
            return match_conn;
        }
    }

    return NULL;
}

static char *
sbus_match_rule_key(TALLOC_CTX *mem_ctx,
                    const char *interface,
                    const char *member)
{
    if (interface == NULL) {
        return NULL;
    }

    if (member == NULL) {
        return talloc_strdup(mem_ctx, interface);
    }

    return talloc_asprintf(mem_ctx, "%s.%s", interface, member);
}

static struct sss_ptr_list *
sbus_match_rule_create(struct sbus_server *server,
                       const char *key)
{
    struct sss_ptr_list *list;
    errno_t ret;

    list = sss_ptr_list_create(NULL, false);
    if (list == NULL) {
        return NULL;
    }

    ret = sss_ptr_hash_add(server->match_rules, key, list, struct sss_ptr_list);
    if (ret != EOK) {
        talloc_free(list);
        return NULL;
    }

    talloc_steal(server->match_rules, list);

    return list;
}


static struct sss_ptr_list *
sbus_match_rule_get(struct sbus_server *server,
                    const char *interface,
                    const char *member,
                    bool create,
                    bool *_created)
{
    struct sss_ptr_list *list;
    char *key;

    key = sbus_match_rule_key(NULL, interface, member);
    if (key == NULL) {
        return NULL;
    }

    list = sss_ptr_hash_lookup(server->match_rules, key, struct sss_ptr_list);
    if (!create || list != NULL) {
        if (_created != NULL) {
            *_created = false;
        }
        goto done;
    }

    list = sbus_match_rule_create(server, key);
    if (list != NULL && _created != NULL) {
        *_created = true;
    }

done:
    talloc_free(key);
    return list;
}

static errno_t
sbus_match_rule_add(struct sbus_server *server,
                    struct sbus_connection *conn,
                    struct sbus_rule *rule)
{
    struct sbus_connection *match_conn;
    struct sss_ptr_list *list;
    bool created = false;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_ALL, "Adding match rule for %s: %s.%s\n",
          conn->unique_name, rule->interface, rule->member);

    list = sbus_match_rule_get(server, rule->interface, rule->member,
                               true, &created);
    if (list == NULL) {
        return ENOMEM;
    }

    match_conn = sbus_match_find(list, conn);
    if (match_conn != NULL) {
        /* Match was already added. */
        return EOK;
    }

    ret = sss_ptr_list_add(list, conn);
    if (ret != EOK && created) {
        talloc_free(list);
    }

    return ret;
}

static errno_t
sbus_match_rule_remove(struct sbus_server *server,
                       struct sbus_connection *conn,
                       struct sbus_rule *rule)
{
    struct sbus_connection *match_conn;
    struct sss_ptr_list *list;

    DEBUG(SSSDBG_TRACE_ALL, "Removing match rule for %s: %s.%s\n",
          conn->unique_name, rule->interface, rule->member);

    list = sbus_match_rule_get(server, rule->interface, rule->member,
                               false, NULL);
    if (list == NULL) {
        return EOK;
    }

    match_conn = sbus_match_find(list, conn);
    if (match_conn == NULL) {
        return EOK;
    }

    sss_ptr_list_remove(list, match_conn);

    if (sss_ptr_list_is_empty(list)) {
        /* This will remove the list from the hash table. */
        talloc_free(list);
    }

    return EOK;
}

static struct sss_ptr_list *
sbus_match_rule_find(struct sbus_server *server,
                     const char *interface,
                     const char *member)
{
    return sbus_match_rule_get(server, interface, member, false, NULL);
}

static errno_t
sbus_match_rule_parse_value(TALLOC_CTX *mem_ctx,
                            const char *item,
                            const char *name,
                            const char **_value)
{
    size_t name_len = strlen(name);
    size_t iter_len;
    const char *iter;
    char quote;

    if (strncmp(item, name, name_len) != 0) {
        return ENOENT;
    }

    iter = item + name_len;

    if (*iter == '=') {
        iter++;
    } else {
        return ENOENT;
    }

    if (*iter == '"' || *iter == '\'') {
        quote = *iter;
        iter++;
    } else {
        return EINVAL;
    }

    iter_len = strlen(iter);
    if (iter[iter_len - 1] != quote) {
        return EINVAL;
    }

    *_value = talloc_strndup(mem_ctx, iter, iter_len - 1);
    if (*_value == NULL) {
        return ENOMEM;
    }

    return EOK;
}

static errno_t
sbus_match_rule_parse_keys(TALLOC_CTX *mem_ctx,
                           char **tokens,
                           struct sbus_rule **_rule)
{
    struct sbus_rule *rule;
    errno_t ret;
    int i, j;

    rule = talloc_zero(mem_ctx, struct sbus_rule);
    if (rule == NULL) {
        return ENOMEM;
    }

    struct {
        const char *name;
        const char **value;
    } keys[] = {
        {"type", &rule->type},
        {"interface", &rule->interface},
        {"member", &rule->member},
        /* There are more keys in D-Bus specification, such as sender, path
         * and destination. But we are not interested in them yet. */
        {NULL, NULL}
    };

    for (i = 0; tokens[i] != NULL; i++) {
        for (j = 0; keys[j].name != NULL; j++) {
            ret = sbus_match_rule_parse_value(rule, tokens[i],
                                              keys[j].name, keys[j].value);
            if (ret == EOK) {
                break;
            } else if (ret == ENOENT) {
                continue;
            }

            /* Error. */
            talloc_free(rule);
            return ret;
        }
    }

    *_rule = rule;
    return EOK;
}

static errno_t
sbus_match_rule_parse_check(struct sbus_rule *rule)
{
    if (rule->type == NULL || strcmp(rule->type, "signal") != 0) {
        return EINVAL;
    }

    if (rule->interface == NULL || rule->member == NULL) {
        return EINVAL;
    }

    return EOK;
}

static errno_t
sbus_match_rule_parse(TALLOC_CTX *mem_ctx,
                      const char *dbus_rule,
                      struct sbus_rule **_rule)
{
    struct sbus_rule *sbus_rule;
    char **tokens;
    errno_t ret;
    int count;

    ret = split_on_separator(NULL, dbus_rule, ',', true, true, &tokens, &count);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_match_rule_parse_keys(mem_ctx, tokens, &sbus_rule);
    talloc_free(tokens);
    if (ret != EOK) {
        goto done;
    }

    ret = sbus_match_rule_parse_check(sbus_rule);
    if (ret != EOK) {
        talloc_free(sbus_rule);
        goto done;
    }

    *_rule = sbus_rule;

    ret = EOK;

done:
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to parse rule [%s] [%d]: %s\n",
              dbus_rule, ret, sss_strerror(ret));
    }


    return ret;
}

errno_t
sbus_server_add_match(struct sbus_server *server,
                      struct sbus_connection *conn,
                      const char *dbus_rule)
{
    struct sbus_rule *sbus_rule;
    errno_t ret;

    ret = sbus_match_rule_parse(NULL, dbus_rule, &sbus_rule);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_match_rule_add(server, conn, sbus_rule);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to add rule [%s] [%d]: %s\n",
              dbus_rule, ret, sss_strerror(ret));
    }

    talloc_free(sbus_rule);
    return ret;
}

errno_t
sbus_server_remove_match(struct sbus_server *server,
                         struct sbus_connection *conn,
                         const char *dbus_rule)
{
    struct sbus_rule *sbus_rule;
    errno_t ret;

    ret = sbus_match_rule_parse(NULL, dbus_rule, &sbus_rule);
    if (ret != EOK) {
        return ret;
    }

    ret = sbus_match_rule_remove(server, conn, sbus_rule);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to remove rule [%s] [%d]: %s\n",
              dbus_rule, ret, sss_strerror(ret));
    }

    talloc_free(sbus_rule);
    return ret;
}

static bool
sbus_server_connection_has_name(struct sbus_server *server,
                                struct sbus_connection *conn,
                                const char *name)
{
    struct sbus_connection *named_conn;

    named_conn = sss_ptr_hash_lookup(server->names, name,
                                     struct sbus_connection);

    if (named_conn == NULL || named_conn != conn) {
        return false;
    }

    return true;
}

errno_t
sbus_server_matchmaker(struct sbus_server *server,
                       struct sbus_connection *conn,
                       const char *avoid_name,
                       DBusMessage *message)
{
    struct sss_ptr_list *list;
    struct sbus_connection *match_conn;
    bool has_name;

    /* We can't really send signals when the server is being destroyed. */
    if (server == NULL || server->disconnecting) {
        return EOK;
    }

    list = sbus_match_rule_find(server,
                                dbus_message_get_interface(message),
                                dbus_message_get_member(message));
    if (list == NULL) {
        /* No connection listens for this signal. */
        return EOK;
    }

    SSS_PTR_LIST_FOR_EACH(list, match_conn, struct sbus_connection) {
        /* Do not send signal back to the sender. */
        if (match_conn == conn) {
            continue;
        }

        /* Sometimes (e.g. when a name is being deleted), we do not want to
         * send the signal to a specific name. */
        if (avoid_name != NULL) {
            has_name = sbus_server_connection_has_name(server, match_conn,
                                                       avoid_name);
            if (has_name) {
                continue;
            }
        }

        dbus_connection_send(match_conn->connection, message, NULL);
    }

    return EOK;
}
