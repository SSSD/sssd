/*
    Authors:
        Jan Cholasta <jcholast@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include <stdlib.h>

#include "util/util.h"

int main(void)
{
    ERROR("\n"
          "******************************************************************************\n"
          "Your system is configured to use the obsolete tool sss_ssh_knownhostsproxy.\n"
          "Please read the sss_ssh_knownhosts(1) man page to learn about its replacement.\n"
          "******************************************************************************\n"
          "\n");

    return EXIT_FAILURE;
}
