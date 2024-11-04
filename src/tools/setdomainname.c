/*
    Copyright (C) 2024 Red Hat

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

#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>


int main(int argc, const char *argv[])
{
    if (argc != 2) {
        return EINVAL;
    }

    if ((argv[1] == NULL) || (argv[1][0] == 0)) {
        return EINVAL;
    }

    errno = 0;
    setdomainname(argv[1], strlen(argv[1]));

    return errno;
}
