#
# Abstract passwd/group entry management
#
# Copyright (c) 2015 Red Hat, Inc.
# Author: Nikolai Kondrashov <Nikolai.Kondrashov@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from pprint import pformat
import pwd
import grp

_PASSWD_LIST_DESC = {None: ("user", {})}
_GROUP_DESC = {"mem": ("member list", {None: ("member", {})})}
_GROUP_LIST_DESC = {None: ("group", _GROUP_DESC)}


def _get_desc(desc_map, key):
    """
    Get an item description from a container description map.

    Arguments:
    desc_map    Container description map.
    key         Item key, None for wildcard description.
    """
    assert isinstance(desc_map, dict)
    if key in desc_map:
        return desc_map[key]
    if None in desc_map:
        desc = desc_map[None]
        if key is not None:
            desc = (desc[0] + " " + pformat(key), desc[1])
        return desc
    elif key is None:
        return ("item", {})
    else:
        return (pformat(key), {})


def _diff(ent, pattern, desc_map={}):
    """
    Describe difference between an entry and a pattern.
    Return None, if none.

    Arguments:
    ent         Entry.
    pattern     Pattern.
    desc_map    Container pattern description map.

    An entry is a value, a list of entries, or a dictionary of entries.
    Entries are used to store passwd and group database entries as
    dictionaries, in lists and dictionaries.

    A pattern is a value, a tuple, a list, or a dictionary of patterns.

    E.g. 123, "abc", [ 123, "abc" ], { "abc": 123 }, { "abc": ( 123 ) }

    A pattern can be matched against a value, a list, or a dictionary entry.

    A value is considered matching, if it's equal to the pattern.

    E.g. 123 == 123, 123 != 456, "abc" == "abc", "abc" != "def", 123 != "abc"

    A list is considered matching a pattern, if the pattern is a list or a
    tuple, where each of pattern list items matches an entry list item and
    vice versa, or where each pattern tuple item matches an entry list item,
    but not necessarily the other way around.

    E.g. [] != "abc", [] == [], [ "abc", 123 ] == [ 123, "abc" ],
         [ "abc" ] != [ 123 ], [ 123 ] != [],
         [] == (), [ "abc", 123 ] == ( 123, "abc" ),
         [ "abc" ] != ( 123 ), [ 123 ] == (), [ 123, "abc" ] == ( 123 )

    NOTE: For the sake of readability, it is recommended to use
          "contains_only" function to create patterns matching all entry list
          items (list patterns), and "contains" function to create patterns
          matching a subset of entry list items (tuple patterns).

    A dictionary is considered matching a pattern, if it is also a dictionary,
    and all of pattern values match identically-keyed values of the
    dictionary.

    E.g. {} == {}, {} != "abc", { "abc": 123, "def": 456 } == { "abc": 123 },
         { "abc": 123 } == {}

    Container pattern description map is a dictionary with keys being item
    keys/indices and values being (name, description map) tuples. None key
    points to a wildcard description, others to specific item descriptions.
    The description map argument is optional, and is used to generate more
    readable difference explanations.
    """
    assert isinstance(desc_map, dict)

    if isinstance(pattern, dict):
        if not isinstance(ent, dict):
            return "not a dict, " + str(type(ent))

        for key, value in pattern.items():
            item_name, item_map = _get_desc(desc_map, key)
            d = _diff(ent[key], value, item_map)
            if d:
                return item_name + " mismatch: " + d
    elif isinstance(pattern, tuple):
        if not isinstance(ent, list):
            return "not a list, " + str(type(ent))

        pattern_matches = [0 for pv in pattern]

        for ei, ev in enumerate(ent):
            for pi, pv in enumerate(pattern):
                d = _diff(ev, pv)
                if not d:
                    pattern_matches[pi] += 1

        unmatched_pattern = [pattern[pi] for pi in range(0, len(pattern))
                             if pattern_matches[pi] == 0]

        items = _get_desc(desc_map, None)[0] + "s"
        if len(unmatched_pattern) > 0:
            return "\nexpected " + items + " not found:\n" + \
                pformat(unmatched_pattern)
    elif isinstance(pattern, list):
        if not isinstance(ent, list):
            return "not a list, " + str(type(ent))

        pattern_matches = [0 for pv in pattern]
        ent_matches = [0 for ev in ent]

        for ei, ev in enumerate(ent):
            for pi, pv in enumerate(pattern):
                d = _diff(ev, pv)
                if not d:
                    pattern_matches[pi] += 1
                    ent_matches[ei] += 1

        unmatched_pattern = [pattern[pi] for pi in range(0, len(pattern))
                             if pattern_matches[pi] == 0]
        unmatched_ent = [ent[pi] for pi in range(0, len(ent))
                         if ent_matches[pi] == 0]

        items = _get_desc(desc_map, None)[0] + "s"
        d = ""
        if len(unmatched_pattern) > 0:
            d += "\nexpected " + items + " not found:\n" + \
                pformat(unmatched_pattern)
        if len(unmatched_ent) != 0:
            d += "\nunexpected " + items + " found:\n" + \
                pformat(unmatched_ent)
        if len(d) > 0:
            return d
    else:
        if pattern != ent:
            return pformat(pattern) + " != " + pformat(ent)

    return None


def contains_only(*args):
    """
    Produce a pattern matching all list items against arguments.
    Use this function instead of constructing bare lists, for readability.
    """
    return list(args)


def contains(*args):
    """
    Produce a pattern matching a subset of list items against arguments.
    Use this function instead of constructing bare tuples, for readability.
    """
    return args


def _convert_passwd(passwd):
    """
    Convert a passwd entry returned by pwd module to an entry dictionary.
    """
    return dict(
        name=passwd.pw_name,
        passwd=passwd.pw_passwd,
        uid=passwd.pw_uid,
        gid=passwd.pw_gid,
        gecos=passwd.pw_gecos,
        dir=passwd.pw_dir,
        shell=passwd.pw_shell
    )


def get_passwd_by_name(name):
    """Get a passwd database entry by name."""
    return _convert_passwd(pwd.getpwnam(name))


def get_passwd_by_uid(uid):
    """Get a passwd database entry by UID."""
    return _convert_passwd(pwd.getpwuid(uid))


def assert_passwd_by_name(name, pattern):
    """Assert a passwd entry, retrieved by name, matches a pattern."""
    try:
        ent = get_passwd_by_name(name)
    except KeyError as err:
        assert False, err
    d = _diff(ent, pattern)
    assert not d, d


def assert_passwd_by_uid(uid, pattern):
    """Assert a passwd entry, retrieved by UID, matches a pattern."""
    try:
        ent = get_passwd_by_uid(uid)
    except KeyError as err:
        assert False, err
    d = _diff(ent, pattern)
    assert not d, d


def get_passwd_list():
    """Get passwd database entry list with root user removed."""
    passwd_list = pwd.getpwall()
    for i, v in enumerate(passwd_list):
        if v.pw_name == "root" and v.pw_uid == 0 and v.pw_gid == 0:
            del passwd_list[i]
            return list(map(_convert_passwd, passwd_list))
    raise Exception("no root user found")


def assert_passwd_list(pattern):
    """Assert retrieved passwd list matches a pattern."""
    d = _diff(get_passwd_list(), pattern, _PASSWD_LIST_DESC)
    assert not d, d


def _diff_each_passwd_by_name(pattern_dict):
    """
    Describe difference between each pattern_dict value and a passwd entry
    retrieved by name being the corresponding key.
    """
    try:
        ent = dict((k, get_passwd_by_name(k)) for k in pattern_dict.keys())
    except KeyError as err:
        return str(err)
    return _diff(ent, pattern_dict, _PASSWD_LIST_DESC)


def _diff_each_passwd_by_uid(pattern_dict):
    """
    Describe difference between each pattern_dict value and a passwd entry
    retrieved by UID being the corresponding key.
    """
    try:
        ent = dict((k, get_passwd_by_uid(k)) for k in pattern_dict.keys())
    except KeyError as err:
        return str(err)
    return _diff(ent, pattern_dict, _PASSWD_LIST_DESC)


def _diff_each_passwd_with_name(pattern_seq):
    """
    Describe difference between each pattern in pattern_seq sequence and a
    passwd entry retrieved by name being the pattern's "name" value.
    """
    return _diff_each_passwd_by_name(dict((p["name"], p) for p in pattern_seq))


def _diff_each_passwd_with_uid(pattern_seq):
    """
    Describe difference between each pattern in pattern_seq sequence and a
    passwd entry retrieved by UID being the pattern's "uid" value.
    """
    return _diff_each_passwd_by_uid(dict((p["uid"], p) for p in pattern_seq))


def assert_each_passwd_by_name(pattern_dict):
    """
    Assert each pattern_dict value matches a passwd entry retrieved by
    name being the corresponding key.
    """
    d = _diff_each_passwd_by_name(pattern_dict)
    assert not d, d


def assert_each_passwd_by_uid(pattern_dict):
    """
    Assert each pattern_dict value matches a passwd entry retrieved by
    UID being the corresponding key.
    """
    d = _diff_each_passwd_by_uid(pattern_dict)
    assert not d, d


def assert_each_passwd_with_name(pattern_seq):
    """
    Assert each pattern in pattern_seq sequence matches a passwd entry
    retrieved by name being the pattern's "name" value.
    """
    d = _diff_each_passwd_with_name(pattern_seq)
    assert not d, d


def assert_each_passwd_with_uid(pattern_seq):
    """
    Assert each pattern in pattern_seq sequence matches a passwd entry
    retrieved by UID being the pattern's "uid" value.
    """
    d = _diff_each_passwd_with_uid(pattern_seq)
    assert not d, d


def _diff_passwd(pattern):
    """
    Describe difference between passwd database and a pattern.
    Each pattern entry must have "name" and "uid" attribute.
    """
    d = _diff(get_passwd_list(), pattern, _PASSWD_LIST_DESC)
    if d:
        return "list mismatch: " + d
    d = _diff_each_passwd_with_name(pattern)
    if d:
        return "name retrieval mismatch: " + d
    d = _diff_each_passwd_with_uid(pattern)
    if d:
        return "UID retrieval mismatch: " + d
    return None


def assert_passwd(pattern):
    """
    Assert passwd database matches a pattern.
    Each pattern entry must have "name" and "uid" attribute.
    """
    d = _diff_passwd(pattern)
    assert not d, d


def _convert_group(group):
    """
    Convert a group entry returned by grp module to an entry dictionary.
    """
    return dict(
        name=group.gr_name,
        passwd=group.gr_passwd,
        gid=group.gr_gid,
        mem=group.gr_mem
    )


def get_group_by_name(name):
    """Get a group database entry by name."""
    return _convert_group(grp.getgrnam(name))


def get_group_by_gid(gid):
    """Get a group database entry by GID."""
    return _convert_group(grp.getgrgid(gid))


def assert_group_by_name(name, pattern):
    """Assert a group entry, retrieved by name, matches a pattern."""
    try:
        ent = get_group_by_name(name)
    except KeyError as err:
        assert False, err
    d = _diff(ent, pattern, _GROUP_DESC)
    assert not d, d


def assert_group_by_gid(gid, pattern):
    """Assert a group entry, retrieved by GID, matches a pattern."""
    try:
        ent = get_group_by_gid(gid)
    except KeyError as err:
        assert False, err
    d = _diff(ent, pattern, _GROUP_DESC)
    assert not d, d


def get_group_list():
    """Get group database entry list with root group removed."""
    group_list = grp.getgrall()
    for i, v in enumerate(group_list):
        if v.gr_name == "root" and v.gr_gid == 0:
            del group_list[i]
            return list(map(_convert_group, group_list))
    raise Exception("no root group found")


def assert_group_list(pattern):
    """Assert retrieved group list matches a pattern."""
    d = _diff(get_group_list(), pattern, _GROUP_LIST_DESC)
    assert not d, d


def _diff_each_group_by_name(pattern_dict):
    """
    Describe difference between each pattern_dict value and a group entry
    retrieved by name being the corresponding key.
    """
    try:
        ent = dict((k, get_group_by_name(k)) for k in pattern_dict.keys())
    except KeyError as err:
        return str(err)
    return _diff(ent, pattern_dict, _GROUP_LIST_DESC)


def _diff_each_group_by_gid(pattern_dict):
    """
    Describe difference between each pattern_dict value and a group entry
    retrieved by GID being the corresponding key.
    """
    try:
        ent = dict((k, get_group_by_gid(k)) for k in pattern_dict.keys())
    except KeyError as err:
        return str(err)
    return _diff(ent, pattern_dict, _GROUP_LIST_DESC)


def _diff_each_group_with_name(pattern_seq):
    """
    Describe difference between each pattern in pattern_seq sequence and a
    group entry retrieved name being the pattern's "name" value.
    """
    return _diff_each_group_by_name(dict((p["name"], p) for p in pattern_seq))


def _diff_each_group_with_gid(pattern_seq):
    """
    Describe difference between each pattern in pattern_seq sequence and a
    group entry retrieved by GID being the pattern's "gid" value.
    """
    return _diff_each_group_by_gid(dict((p["gid"], p) for p in pattern_seq))


def assert_each_group_by_name(pattern_dict):
    """
    Assert each pattern_dict value matches a group entry retrieved by
    name being the corresponding key.
    """
    d = _diff_each_group_by_name(pattern_dict)
    assert not d, d


def assert_each_group_by_gid(pattern_dict):
    """
    Assert each pattern_dict value matches a group entry retrieved by
    GID being the corresponding key.
    """
    d = _diff_each_group_by_gid(pattern_dict)
    assert not d, d


def assert_each_group_with_name(pattern_seq):
    """
    Assert each pattern in pattern_seq sequence matches a group entry
    retrieved by name being the pattern's "name" value.
    """
    d = _diff_each_group_with_name(pattern_seq)
    assert not d, d


def assert_each_group_with_gid(pattern_seq):
    """
    Assert each pattern in pattern_seq sequence matches a group entry
    retrieved by GID being the pattern's "gid" value.
    """
    d = _diff_each_group_with_gid(pattern_seq)
    assert not d, d


def _diff_group(pattern):
    """
    Describe difference between group database and a pattern.
    Each pattern entry must have "name" and "gid" attribute.
    """
    d = _diff(get_group_list(), pattern, _GROUP_LIST_DESC)
    if d:
        return "list mismatch: " + d
    d = _diff_each_group_with_name(pattern)
    if d:
        return "name retrieval mismatch: " + d
    d = _diff_each_group_with_gid(pattern)
    if d:
        return "GID retrieval mismatch: " + d
    return None


def assert_group(pattern):
    """
    Assert group database matches a pattern.
    Each pattern entry must have "name" and "gid" attribute.
    """
    d = _diff_group(pattern)
    assert not d, d
