#
# Various functions
#
# Copyright (c) 2015 Red Hat, Inc.
# Author: Nikolai Kondrashov <Nikolai.Kondrashov@redhat.com>
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import re
import os
import subprocess

UNINDENT_RE = re.compile("^ +", re.MULTILINE)


def unindent(text):
    """
        Unindent text by removing at most the number of spaces present in
        the first non-empty line from the beginning of every line.
    """
    indent_ref = [0]
    def replace(match):
        if indent_ref[0] == 0:
            indent_ref[0] = len(match.group())
        return match.group()[indent_ref[0]:]
    return UNINDENT_RE.sub(replace, text)


def run_shell():
    """
        Execute an interactive shell under "screen", preserving environment.
        For use as a breakpoint for debugging.
    """
    subprocess.call([
        "screen", "-D", "-m", "bash", "-c",
        "PATH='" + os.getenv("PATH", "") + "' " +
        "LD_LIBRARY_PATH='" + os.getenv("LD_LIBRARY_PATH", "") + "' " +
        "LD_PRELOAD='" + os.getenv("LD_PRELOAD", "") + "' " +
        "bash -i"
    ])


def first_dir(*args):
    """Return first argument that points to an existing directory."""
    for arg in args:
        if os.path.isdir(arg):
            return arg
