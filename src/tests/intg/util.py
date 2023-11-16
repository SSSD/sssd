#
# Various functions
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

import re
import os
import sys
import subprocess
import config
import shutil

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
    my_env = os.environ.copy()
    my_env["ROOT_DIR"] = config.PREFIX

    # screen filter out LD_* evniroment varibles.
    # Back-up them and set them later in screenrc
    my_env["_LD_LIBRARY_PATH"] = os.getenv("LD_LIBRARY_PATH", "")
    my_env["_LD_PRELOAD"] = os.getenv("LD_PRELOAD", "")

    subprocess.call([
        "screen", "-DAm", "-S", "sssd_cwrap_session", "-c",
        ".config/screenrc"],
        env=my_env
    )


def first_dir(*args):
    """Return first argument that points to an existing directory."""
    for arg in args:
        if os.path.isdir(arg):
            return arg


def backup_envvar_file(name):
    path = os.environ[name]
    backup_path = path + ".bak"
    shutil.copyfile(path, backup_path)
    return path


def restore_envvar_file(name):
    path = os.environ[name]
    backup_path = path + ".bak"
    os.rename(backup_path, path)


def get_call_output(cmd, stderr_output=subprocess.PIPE, check=False, custom_env=None):
    """
        Executes the provided command.
        When check is set to True, this function will throw an exception
        if the command returns with a non-zero value.
    """

    if (sys.version_info.major < 3
            or (sys.version_info.major == 3 and sys.version_info.minor < 7)):
        try:
            output = subprocess.check_output(cmd, universal_newlines=True,
                                             stderr=stderr_output, env=custom_env)
        except subprocess.CalledProcessError as err:
            if (not check):
                output = err.output
            else:
                raise err
        return output

    process = subprocess.run(cmd, check=check, text=True,
                             stdout=subprocess.PIPE, stderr=stderr_output,
                             env=custom_env)
    return process.stdout
