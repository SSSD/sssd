#!/usr/bin/env bash
#
# Generate release notes for sssd.io

set -euo pipefail

FROM=""
TO="HEAD"
VERSION=""
FORMAT="rst"
scriptdir=`realpath \`dirname "$0"\``

while [[ $# -gt 0 ]]; do
    case $1 in
        --from=*)
            FROM="${1#*=}"
            shift
            ;;
        --from)
            FROM="$2"
            shift 2
            ;;
        --to=*)
            TO="${1#*=}"
            shift
            ;;
        --to)
            TO="$2"
            shift 2
            ;;
        --version=*)
            VERSION="${1#*=}"
            shift
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: $0 --from <ref> --to <ref> --version <version>" >&2
            exit 1
            ;;
    esac
done

notes=`$scriptdir/release-notes.py --from $FROM --to $TO --version $VERSION --format $FORMAT`
fixed_issues=`$scriptdir/fixed-issues.sh --from $FROM --to $TO --format $FORMAT`
gitlog=`git shortlog --pretty=format:"%h  %s" -w0,4 $FROM..$TO`

echo "$notes"
echo ""
echo "Tickets Fixed"
echo "-------------"
echo ""
echo "$fixed_issues"
echo ""
echo "Detailed Changelog"
echo "------------------"
echo ""
echo ".. code-block:: release-notes-shortlog"
echo ""
echo "    $ git shortlog --pretty=format:"%h  %s" -w0,4 $FROM..$TO"
echo ""
echo "$gitlog" | sed 's/^/    /'
echo ""
