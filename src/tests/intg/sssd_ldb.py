#
# SSSD integration test - access the ldb cache
#
# Copyright (c) 2016 Red Hat, Inc.
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

import os
import ldb
import config


class CacheType(object):
    sysdb = 1
    timestamps = 2


class TsCacheEntry(object):
    user = 1
    group = 2


class SssdLdb(object):
    def __init__(self, domain_name):
        self._domain_name = domain_name
        self._sysdb = self._create_dbconn(CacheType.sysdb,
                                          domain_name)
        self._timestamps = self._create_dbconn(CacheType.timestamps,
                                               domain_name)

    def _create_dbconn(self, cache_type, domain_name):
        if cache_type == CacheType.sysdb:
            db_path = os.path.join(config.DB_PATH,
                                   "cache_%s.ldb" % domain_name)
        elif cache_type == CacheType.timestamps:
            db_path = os.path.join(config.DB_PATH,
                                   "timestamps_%s.ldb" % domain_name)
        else:
            raise ValueError("Unknown cache type\n")

        pyldb = ldb.Ldb()
        pyldb.connect(db_path)
        return pyldb

    def _get_dbconn(self, cache_type):
        dbconn = None
        if cache_type == CacheType.sysdb:
            dbconn = self._sysdb
        elif cache_type == CacheType.timestamps:
            dbconn = self._timestamps
        return dbconn

    def _entry_basedn(self, entry_type):
        if entry_type == TsCacheEntry.user:
            rdn = "users"
        elif entry_type == TsCacheEntry.group:
            rdn = "groups"
        else:
            raise ValueError("Unknown entry type\n")
        return "cn=%s,cn=%s,cn=sysdb" % (rdn, self._domain_name)

    def _basedn(self, name, domain, entry_type):
        return "name=%s@%s,%s" % (name, domain.lower(),
                                  self._entry_basedn(entry_type))

    def get_entry_attr(self, cache_type, entry_type, name, domain, attr):
        dbconn = self._get_dbconn(cache_type)
        basedn = self._basedn(name, domain, entry_type)

        res = dbconn.search(base=basedn, scope=ldb.SCOPE_BASE, attrs=[attr])
        if res.count != 1:
            return None

        return res.msgs[0].get(attr).get(0)

    def invalidate_entry(self, name, entry_type, domain):
        dbconn = self._get_dbconn(CacheType.timestamps)

        m = ldb.Message()
        m.dn = ldb.Dn(dbconn, self._basedn(name, domain, entry_type))
        m["dataExpireTimestamp"] = ldb.MessageElement(str(1),
                                                      ldb.FLAG_MOD_REPLACE,
                                                      "dataExpireTimestamp")
        dbconn.modify(m)
