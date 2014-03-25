#
# Miscellaneous routines.
#
# Copyright (C) 2014 Red Hat
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

if [ -z ${_MISC_SH+set} ]; then
declare -r _MISC_SH=

# Remove files and directories recursively, forcing write permissions on
# directories.
# Args: path...
function rm_rf_ro()
{
    chmod -Rf u+w -- "$@" || true
    rm -Rf -- "$@"
}

# Run "scan-build" with output to a single specified directory, instead of
# a subdirectory.
# Args: dir [scan_build_arg...]
function scan_build_single()
{
    declare -r dir="$1";    shift
    declare entry
    declare subdir
    declare status

    set +o errexit
    scan-build -o "$dir" "$@"
    status="$?"
    set -o errexit

    for entry in "$dir/"*; do
        if [ -n "${subdir+set}" ] || ! [ -d "$entry" ]; then
            echo 'Unexpected entries in scan-build output directory' >&2
            exit 1
        fi
        subdir="$entry"
    done

    mv "$subdir/"* "$dir"
    rmdir "$subdir"
    return "$status"
}

# Check if a scan-build result directory has any non-empty .plist files.
# Args: dir
function scan_check()
{
    declare -r dir="$1"
    declare f
    for f in "$dir"/*.plist; do
        if [ "`xqilla -i \"\$f\" /dev/stdin \
                <<<'count(/plist/dict/array[count(*) > 0])'`" != 0 ]; then
            return 1
        fi
    done
    return 0
}

# Extract line and function coverage percentage from a "genhtml" or "lcov
# --summary" output.
# Input: "genhtml" or "lcov --summary" output
# Output: lines funcs
function lcov_summary()
{
    sed -ne 's/^ *\(lines\|functions\)\.*: \([0-9]\+\).*$/ \2/p' |
        tr -d '\n'
    echo
}

# Check if a "genhtml" or "lcov --summary" output has a minimum coverage
# percentage of lines and functions.
# Input: "genhtml" or "lcov --summary" output
# Args: min_lines min_funcs
function lcov_check()
{
    declare -r min_lines="$1";      shift
    declare -r min_funcs="$1";      shift
    declare lines
    declare funcs

    read -r lines funcs < <(lcov_summary)
    ((lines >= min_lines && funcs >= min_funcs)) && return 0 || return 1
}

# Check if the current user belongs to a group.
# Args: group_name
function memberof()
{
    declare -r group_name="$1"
    declare group_id
    declare id
    group_id=`getent group "$group_name" | cut -d: -f3` || return 1
    for id in "${GROUPS[@]}"; do
        if [ "$id" == "$group_id" ]; then
            return 0
        fi
    done
    return 1
}

fi # _MISC_SH
