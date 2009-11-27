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

#ifndef __ARES_PARSE_TXT_REPLY_H__
#define __ARES_PARSE_TXT_REPLY_H__

struct ares_txt_reply {
    struct ares_txt_reply  *next;
    unsigned char          *txt;
    size_t                  length;  /* length excludes null termination */
};

int _ares_parse_txt_reply(const unsigned char* abuf, int alen,
                          struct ares_txt_reply **txt_out);

#endif /* __ARES_PARSE_TXT_REPLY_H__ */
