#
#   Authors:
#       Pavel Brezina <pbrezina@redhat.com>
#
#   Copyright (C) 2017 Red Hat
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#


class DataType:
    """ Represents an SBus data type and its corresponding equivalents
        in D-Bus and C code.

        SBus supports also custom types that can be parsed complex C types such
        as hash tables or structures. In this case the SBus type may differ
        from D-Bus type.
    """
    available = {}

    def __init__(self, sbus_type, dbus_type, c_type, key_format,
                 require_talloc):
        self.sbus_type = sbus_type
        self.dbus_type = dbus_type
        self.RequireTalloc = require_talloc

        # Printf formatter (without leading %) if the type supports keying
        self.keyFormat = key_format

        # Input and output C types. For example 'int' and 'int*'
        self.CType = c_type
        self.inputCType = c_type
        self.outputCType = c_type + "*"

    def __del__(self):
        del DataType.available[self.sbus_type]

    def __str__(self):
        return "%s == %s == %s" % (self.sbus_type, self.dbus_type, self.c_type)

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def Find(sbus_type):
        """ Find DataType object of given @sbus_type.
        """
        if not (sbus_type in DataType.available):
            raise ValueError(('Data type "%s" is not currently '
                              'supported by code generator') % sbus_type)

        return DataType.available[sbus_type]

    @staticmethod
    def Create(sbus_type, c_type, KeyFormat=None, DBusType=None,
               RequireTalloc=False):
        """ Create a new SBus type. Specify DBusType if it differs from
            the SBus type. Specify printf formatter KeyFormat if this type
            can be used as a key.
        """
        dbus_type = DBusType if DBusType is not None else sbus_type

        type = DataType(sbus_type, dbus_type, c_type, KeyFormat, RequireTalloc)
        DataType.available[sbus_type] = type

        return type

    @staticmethod
    def SBusToDBusType(sbus_type):
        """ If possible convert SBus data type into D-Bus type. Otherwise
            return unchanged input.
        """
        if not (sbus_type in DataType.available):
            return sbus_type

        return DataType.available[sbus_type].dbus_type
