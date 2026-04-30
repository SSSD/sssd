#!/usr/bin/env bash

set -e

# Group output in Github Job view
function GROUP_START() {
  echo "::group::$1"
}

function GROUP_END() {
  echo "::endgroup::"
}

# Get the stable branch name (sssd-X-Y) from a version string.
function get_stable_branch() {
  local ver="${1%%-*}"
  local x y z
  IFS='.' read -r x y z <<< "$ver"

  echo "sssd-$x-$y"
}

# Get the previous version tag for release notes generation.
# For X.Y.Z releases (Z>0), the previous version is X.Y.(Z-1).
# For X.Y.0 releases (Y>0), the previous version is X.(Y-1).0.
# For X.0.0 releases, the previous version is the latest stable tag
# (matching X.Y.Z, ignoring prereleases) reachable from the branch.
# The prerelease suffix (e.g. -beta1) is stripped before computation.
function get_previous_version() {
  local ver="${1%%-*}"
  local branch="$2"
  local x y z
  IFS='.' read -r x y z <<< "$ver"

  if [[ "$z" -ne 0 ]]; then
    echo "$x.$y.$((z - 1))"
  elif [[ "$y" -ne 0 ]]; then
    echo "$x.$((y - 1)).0"
  else
    git tag --merged "$branch" --sort=-v:refname | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | head -1
  fi
}

# Usage
if [ "$#" -lt 2 ] || [ "$#" -gt 5 ]; then
  echo "Usage: $0 <branch> <version> [<create-stable-branch>] [<github-repo> <git-remote>]" >&2
  exit 1
fi

tmpdir=$(mktemp -d)
scriptdir=`realpath \`dirname "$0"\``
rootdir=`realpath "$scriptdir/.."`
branch=$1
version=$2
create_stable_branch="${3:-auto}"
prev_version=$(get_previous_version "$version" "$branch")
if [[ -z "$prev_version" ]]; then
  echo "Error: Could not determine the previous version tag. Ensure the repository is up to date and tags are fetched." >&2
  exit 1
fi
stable_branch=$(get_stable_branch "$version")
backport_label="backport-to-$stable_branch"
github_repo="${4:-SSSD/sssd}"
git_remote="${5:-origin}"

# Resolve "auto": create stable branch when releasing from master
# "no" can be used for pre-releases where the release is still developed
# on the master branch.
if [[ "$create_stable_branch" == "auto" ]]; then
  if [[ "$branch" == "master" ]]; then
    create_stable_branch="yes"
  else
    create_stable_branch="no"
  fi
fi

echo "SSSD sources location: $rootdir"
echo "Repository: $github_repo"
echo "Remote: $git_remote"
echo "Temporary directory: $tmpdir"
echo "Target branch: $branch"
echo "Stable branch: $stable_branch (will be created: $create_stable_branch)"
echo "Backport label: $backport_label (will be created: $create_stable_branch)"
echo "Released version: $version"
echo "Previous version: $prev_version"

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
git fetch "$git_remote" "$branch"
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

GROUP_START "Generate release notes"
"$scriptdir/generate-full-release-notes.sh" --from "$prev_version" --to "$version" --version "$version" > "/tmp/sssd-$version.rst"
echo "Release notes stored at /tmp/sssd-$version.rst"
GROUP_END

GROUP_START "Authenticate git commands"
gh auth setup-git
GROUP_END

GROUP_START "Push commits and tag"
git push "$git_remote" "$branch"
git push "$git_remote" "$version"
GROUP_END

if [[ "$create_stable_branch" == "yes" ]]; then
GROUP_START "Create stable branch"
git checkout -b "$stable_branch" "$version"
git push "$git_remote" "$stable_branch"
GROUP_END

GROUP_START "Create backport label"
if ! gh label list --repo "$github_repo" --search "$backport_label" --json name --jq '.[].name' | grep -Fxq "$backport_label"; then
  gh label create "$backport_label" --color "ededed" --repo "$github_repo"
fi
GROUP_END
fi

GROUP_START "Create GitHub release"
gh release create "$version" \
    --repo "$github_repo" \
    --title "sssd-$version" \
    --notes "[**See full release notes here.**](https://sssd.io/release-notes/sssd-$version.html)" \
    --generate-notes \
    --verify-tag \
    --draft \
    "sssd-${version}.tar.gz" \
    "sssd-${version}.tar.gz.asc" \
    "sssd-${version}.tar.gz.sha256sum"
GROUP_END
