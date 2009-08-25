/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

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

#ifndef __ARES_PARSE_SRV_REPLY_H__
#define __ARES_PARSE_SRV_REPLY_H__

struct srv_reply {
    u_int16_t weight;
    u_int16_t priority;
    u_int16_t port;
    char *host;
};

int _ares_parse_srv_reply (const unsigned char *abuf, int alen,
                           struct srv_reply **srv_out, int *nsrvreply);

#endif /* __ARES_PARSE_SRV_REPLY_H__ */
