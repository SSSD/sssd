#
# Secrets responder test client
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

import socket
import requests

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.connection import HTTPConnection
from requests.packages.urllib3.connectionpool import HTTPConnectionPool
from requests.compat import quote, unquote, urlparse


class HTTPUnixConnection(HTTPConnection):
    def __init__(self, host, timeout=60, **kwargs):
        super(HTTPUnixConnection, self).__init__('localhost')
        self.unix_socket = host
        self.timeout = timeout

    def connect(self):
        sock = socket.socket(family=socket.AF_UNIX)
        sock.settimeout(self.timeout)
        sock.connect(self.unix_socket)
        self.sock = sock


class HTTPUnixConnectionPool(HTTPConnectionPool):
    scheme = 'http+unix'
    ConnectionCls = HTTPUnixConnection


class HTTPUnixAdapter(HTTPAdapter):
    def get_connection(self, url, proxies=None):
        # proxies, silently ignored
        path = unquote(urlparse(url).netloc)
        return HTTPUnixConnectionPool(path)


class SecretsHttpClient(object):
    secrets_sock_path = '/var/run/secrets.socket'
    secrets_container = 'secrets'

    def __init__(self, content_type='application/json', sock_path=None):
        if sock_path is None:
            sock_path = self.secrets_sock_path

        self.content_type = content_type
        self.session = requests.Session()
        self.session.mount('http+unix://', HTTPUnixAdapter())
        self.headers = dict({'Content-Type': content_type})
        self.url = 'http+unix://' + \
            quote(sock_path, safe='') + \
            '/' + \
            self.secrets_container
        self._last_response = None

    def _join_url(self, resource):
        path = self.url.rstrip('/') + '/'
        if resource is not None:
            path = path + resource.lstrip('/')
        return path

    def _add_headers(self, **kwargs):
        headers = kwargs.get('headers', None)
        if headers is None:
            headers = dict()
        headers.update(self.headers)
        return headers

    def _request(self, cmd, path, **kwargs):
        self._last_response = None
        url = self._join_url(path)
        kwargs['headers'] = self._add_headers(**kwargs)
        self._last_response = cmd(url, **kwargs)
        return self._last_response

    @property
    def last_response(self):
        return self._last_response

    def get(self, path, **kwargs):
        return self._request(self.session.get, path, **kwargs)

    def list(self, **kwargs):
        return self._request(self.session.get, None, **kwargs)

    def put(self, name, **kwargs):
        return self._request(self.session.put, name, **kwargs)

    def delete(self, name, **kwargs):
        return self._request(self.session.delete, name, **kwargs)

    def post(self, name, **kwargs):
        return self._request(self.session.post, name, **kwargs)


class SecretsLocalClient(SecretsHttpClient):
    def list_secrets(self):
        res = self.list()
        res.raise_for_status()
        simple = res.json()
        return simple

    def get_secret(self, name):
        res = self.get(name)
        res.raise_for_status()
        simple = res.json()
        ktype = simple.get("type", None)
        if ktype != "simple":
            raise TypeError("Invalid key type: %s" % ktype)
        return simple["value"]

    def set_secret(self, name, value):
        res = self.put(name, json={"type": "simple", "value": value})
        res.raise_for_status()

    def del_secret(self, name):
        res = self.delete(name)
        res.raise_for_status()

    def create_container(self, name):
        res = self.post(name)
        res.raise_for_status()
