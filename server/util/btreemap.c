/*
 SSSD

 Service monitor

 Copyright (C) Stephen Gallagher	2008

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

#include "talloc.h"
#include "util/btreemap.h"
#include "util/util.h"

struct btreemap
{
    /* NULL keys are not allowed */
    void *key;

    /* NULL values are permitted */
    void *value;

    struct btreemap *left;
    struct btreemap *right;

    /* comparator must return -1, 0 or 1
     * and should only be set for the root node
     * other nodes will be ignored.
     */
    btreemap_comparison_fn comparator;
};

/* btreemap_search_key
 * Searches a btreemap for an entry with a specific key
 * If found, it will return BTREEMAP_FOUND and node will
 * be set to the appropriate node.
 * If not found, it will set the following:
 * BTREEMAP_EMPTY: The map was empty, create a new map when adding keys
 * BTREEMAP_CREATE_LEFT: A new node created should use node->left
 * BTREEMAP_CREATE_RIGHT: A new node created should use node->right
 */
int btreemap_search_key(struct btreemap *map, void *key, struct btreemap **node)
{
    struct btreemap *tempnode;
    int result;
    int found = BTREEMAP_EMPTY;

    if (!map)
    {
        *node = NULL;
        return BTREEMAP_EMPTY;
    }

    tempnode = map;
    while (found == BTREEMAP_EMPTY) {
        result = tempnode->comparator(tempnode->key, key);
        if (result > 0)
        {
            if (tempnode->right)
                tempnode=tempnode->right;
            else
            {
                found = BTREEMAP_CREATE_RIGHT;
            }
        } else if (result < 0)
        {
            if (tempnode->left)
                tempnode=tempnode->left;
            else
            {
                found = BTREEMAP_CREATE_LEFT;
            }
        } else
        {
            /* This entry matched */
            found = BTREEMAP_FOUND;
        }
    }

    *node = tempnode;
    return found;
}

void *btreemap_get_value(struct btreemap *map, void *key)
{
    struct btreemap *node;
    int found;

    if (!map || !key)
    {
        return NULL;
    }

    /* Search for the key */
    found = btreemap_search_key(map, key, &node);
    if (found == 0)
    {
        return node->value;
    }

    /* If the key was not found, return NULL */
    return NULL;
}

int btreemap_set_value(struct btreemap **map, void *key, void *value,
                       btreemap_comparison_fn comparator)
{
    struct btreemap *node;
    struct btreemap *new_node;
    int found;

    if (!key)
    {
        return EINVAL;
    }

    /* Search for the key */
    found = btreemap_search_key(*map, key, &node);
    if (found == BTREEMAP_FOUND)
    {
        /* Update existing value */
        node->value = value;
        return EOK;
    }

    /* Need to add a value to the tree */
    new_node = talloc_zero(node, struct btreemap);
    if (!new_node)
    {
        return ENOMEM;
    }
    new_node->key = talloc_steal(*map, key);
    new_node->value = talloc_steal(*map, value);
    new_node->comparator = comparator;

    if (found == BTREEMAP_EMPTY)
    {
        *map = new_node;
    }
    if (found == BTREEMAP_CREATE_LEFT)
    {
        node->left = new_node;
    } else if (found == BTREEMAP_CREATE_RIGHT)
    {
        node->right = new_node;
    }
    return EOK;
}

struct btreemap *btreemap_new(void *key, void *value,
                              btreemap_comparison_fn comparator)
{
    struct btreemap *map;
    int result;

    map = NULL;
    result = btreemap_set_value(&map, key, value, comparator);
    if (result != EOK)
    {
        return NULL;
    }

    return map;
}
