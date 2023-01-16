from __future__ import annotations

from typing import Any


def attrs_parse(lines: list[str], attrs: list[str] | None = None) -> dict[str, list[str]]:
    """
    Parse LDAP attributes from output.

    :param lines: Output.
    :type lines: list[str]
    :param attrs: If set, only requested attributes are returned, defaults to None
    :type attrs: list[str] | None, optional
    :return: Dictionary with attribute name as a key.
    :rtype: dict[str, list[str]]
    """
    out: dict[str, list[str]] = {}
    for line in lines:
        line = line.strip()
        if not line:
            continue

        (key, value) = map(lambda x: x.strip(), line.split(":", 1))
        if attrs is None or key in attrs:
            out.setdefault(key, [])
            out[key].append(value)

    return out


def attrs_include_value(attr: Any | list[Any] | None, value: Any) -> list[Any]:
    """
    Include ``value`` to attribute list if it is not yet present.

    If ``attr`` is not a list, then it is first converted into a list.

    :param attr: List of attribute values or a single value.
    :type attr: Any | list[Any]
    :param value: Value to add to the list.
    :type value: Any
    :return: New list with the value included.
    :rtype: list[Any]
    """
    attr = to_list(attr)

    if value not in attr:
        return [*attr, value]

    return attr


def to_list(value: Any | list[Any] | None) -> list[Any]:
    """
    Convert value into a list.

    - if value is ``None`` then return an empty list
    - if value is already a list then return it unchanged
    - if value is not a list then return ``[value]``

    :param value: Value that should be converted to a list.
    :type value: Any | list[Any] | None
    :return: List with the value as an element.
    :rtype: list[Any]
    """
    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


def to_list_of_strings(value: Any | list[Any] | None) -> list[str]:
    """
    Convert given list or single value to list of strings.

    The ``value`` is first converted to a list and then ``str(item)`` is run on
    each of its item.

    :param value: Value to convert.
    :type value: Any | list[Any] | None
    :return: List of strings.
    :rtype: list[str]
    """
    return [str(x) for x in to_list(value)]


def to_list_without_none(r_list: list[Any]) -> list[Any]:
    """
    Remove all elements that are ``None`` from the list.

    :param r_list: List of all elements.
    :type r_list: list[Any]
    :return: New list with all values from the given list that are not ``None``.
    :rtype: list[Any]
    """
    return [x for x in r_list if x is not None]
