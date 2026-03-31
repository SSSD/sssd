#!/usr/bin/env bash
#
# Open pull request with release notes against sssd.io

set -e -o pipefail

# Usage
if [ "$#" -ne 4 ]; then
  echo "Usage: $0 <version> <path-to-rn> <fork-user> <fork-token>" >&2
  exit 1
fi

# Create working directory
scriptdir=`realpath \`dirname "$0"\``
wd=`mktemp -d`
trap 'rm -rf "$wd"' EXIT

# Initial setup
VERSION=$1
PATH_TO_RN=$2
FORK_USER=$3
FORK_TOKEN=$4

GITHUB_REPOSITORY="SSSD/sssd.io"
OWNER=`echo "$GITHUB_REPOSITORY" | cut -d / -f 1`
REPOSITORY=`echo "$GITHUB_REPOSITORY" | cut -d / -f 2`
TARGET="master"
RN_BRANCH_NAME="$OWNER-$REPOSITORY-relnotes-$VERSION"

echo "GitHub Repository: $OWNER/$REPOSITORY"
echo "Target Branch: $TARGET"
echo "Release Notes Branch: $RN_BRANCH_NAME"
echo ""
echo "Action Directory: $scriptdir"
echo "Working Directory: $wd"
echo ""

pushd "$wd"
set -x

# Login with token to GitHub CLI, GH_TOKEN variable is used in GitHub Actions
set +x
if [ -z "$GH_TOKEN" ]; then
    echo $FORK_TOKEN > .token
    gh auth login --with-token < .token
    rm -f .token
fi
set -x

# Clone repository and fetch the pull request
git clone "https://github.com/$OWNER/$REPOSITORY.git" .
git remote add "$FORK_USER" "https://$FORK_USER:$FORK_TOKEN@github.com/$FORK_USER/$REPOSITORY.git"
git checkout "$TARGET"
gh repo set-default "$GITHUB_REPOSITORY"

# Create new branch that we will work on
git checkout -b "$RN_BRANCH_NAME" "$TARGET"

# Copy release notes and update releases.rst
# Insert new release before the first occurrence of ".. release::"
cp -f "$PATH_TO_RN" "./src/release-notes/sssd-$VERSION.rst"
TODAY=$(date +%Y-%m-%d)
RELEASES_FILE="./src/releases.rst"
NEW_RELEASE=$(cat <<EOF
    .. release:: sssd-$VERSION
        :date: $TODAY
        :download: https://github.com/SSSD/sssd/releases/tag/$VERSION
EOF
)

awk -i inplace -v new="$NEW_RELEASE" \
    '/^[[:space:]]*\.\. release::/ && !done {print new "\n"; done=1} {print}' \
    "$RELEASES_FILE"

# Commit changes
git add --all
git commit -S -a -m "Release sssd-$VERSION"

# Push backport to remote
git push --set-upstream "$FORK_USER" "$RN_BRANCH_NAME" --force

# Prepare pull request message
BODY_FILE="/tmp/relnotes-message"
cat > "$BODY_FILE" <<EOF
These are automatically generated release notes for sssd-$VERSION.

Please review and edit the notes before merging.

**You can push changes to this pull request**

\`\`\`
git remote add $FORK_USER git@github.com:$FORK_USER/$REPOSITORY.git
git fetch $FORK_USER refs/heads/$RN_BRANCH_NAME
git checkout $RN_BRANCH_NAME
git push $FORK_USER $RN_BRANCH_NAME --force
\`\`\`
EOF

gh pr create \
    --draft \
    --base "$TARGET" \
    --body-file "$BODY_FILE" \
    --head "$FORK_USER:$RN_BRANCH_NAME" \
    --title "Release sssd-$VERSION"
