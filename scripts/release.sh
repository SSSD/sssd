#!/usr/bin/env bash

set -e

# Group output in Github Job view
function GROUP_START() {
  echo "::group::$1"
}

function GROUP_END() {
  echo "::endgroup::"
}

# Usage
if [ "$#" -ne 2 ] && [ "$#" -ne 4 ]; then
  echo "Usage: $0 <branch> <version> [<github-repo> <git-remote>]" >&2
  exit 1
fi

tmpdir=$(mktemp -d)
scriptdir=`realpath \`dirname "$0"\``
rootdir=`realpath "$scriptdir/.."`
branch=$1
version=$2
github_repo="${3:-SSSD/sssd}"
git_remote="${4:-origin}"

echo "SSSD sources location: $rootdir"
echo "Repository: $github_repo"
echo "Remote: $git_remote"
echo "Temporary directory: $tmpdir"
echo "Target branch: $branch"
echo "Released version: $version"

# Work in a temporary copy of the repository
pushd $tmpdir
trap 'rm -rf "$tmpdir"; popd' EXIT
cp -a "$rootdir/." "$tmpdir"

GROUP_START "Check prerequisites"
# Check if required commands are installed
for cmd in git gh autoreconf make sed gpg; do
  if ! command -v "$cmd" &> /dev/null; then
    echo "Error: Required command '$cmd' is not installed." >&2
    exit 1
  fi
done

# Check if there are any opened weblate pull requests
if [ -n "$(gh pr list --author weblate --state open --base \"$branch\" --repo \"$github_repo\")" ]; then
  echo "Error: There are open weblate pull-requests, please merge them first." >&2
  exit 1
fi

# Check if repository is pristine
if [ -n "$(git status --porcelain)" ]; then
  echo "Error: SSSD sources have uncommitted changes." >&2
  exit 1
fi
GROUP_END

set -x

GROUP_START "Checkout branch"
git checkout "$branch"
git pull --rebase
GROUP_END

GROUP_START "Configure SSSD"
autoreconf -if
./configure
GROUP_END

GROUP_START "Update translations"
make update-po
git add po/ src/man/po/
git commit -S -m "pot: update pot files"
GROUP_END

GROUP_START "Commit and tag release"
# Set release version (allow empty commit in case it was already set)
sed -i -E "s/(.+VERSION_NUMBER.+)\\[.+\\](.+)/\1[$version]\2/" version.m4
git add version.m4
git commit -S -m "Release sssd-$version" --allow-empty
git tag -s "$version" -m "Release sssd-$version"
GROUP_END

GROUP_START "Create tarball"
make dist-gzip
GROUP_END

GROUP_START "Sign tarball"
gpg --default-key C13CD07FFB2DB1408E457A3CD3D21B2910CF6759 --detach-sign --armor "sssd-${version}.tar.gz"
sha256sum "sssd-${version}.tar.gz" > "sssd-${version}.tar.gz.sha256sum"
GROUP_END

GROUP_START "Authenticate git commands"
gh auth setup-git
GROUP_END

GROUP_START "Push commits and tag"
git push "$git_remote" "$branch"
git push "$git_remote" "$version"
GROUP_END

GROUP_START "Create GitHub release"
gh release create "$version" \
    --repo "$github_repo" \
    --title "sssd-$version" \
    --generate-notes \
    --verify-tag \
    --draft \
    "sssd-${version}.tar.gz" \
    "sssd-${version}.tar.gz.asc" \
    "sssd-${version}.tar.gz.sha256sum"
GROUP_END
