#!/usr/bin/env bash

set -euo pipefail

# Parse arguments
FROM=""
TO="HEAD"
FORMAT="plain"

# Pattern to find issues
pattern="Resolves: https://github.com/SSSD/sssd/issues/[0-9]+"

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
        --format=*)
            FORMAT="${1#*=}"
            shift
            ;;
        --format)
            FORMAT="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: $0 --from <ref> [--to <ref>] [--format plain|rst|md]" >&2
            exit 1
            ;;
    esac
done

# Validate required arguments
if [[ -z "$FROM" ]]; then
    echo "Error: --from is required" >&2
    echo "Usage: $0 --from <ref> [--to <ref>] [--format plain|rst|md]" >&2
    exit 1
fi

# Validate format
if [[ "$FORMAT" != "plain" && "$FORMAT" != "rst" && "$FORMAT" != "md" ]]; then
    echo "Error: --format must be 'plain', 'rst' or 'md'" >&2
    exit 1
fi

# Extract issue URLs from git log
issue_urls=$(
    git log --pretty=medium --no-abbrev-commit "$FROM..$TO" \
        | grep -oE "$pattern" \
        | sed 's/^Resolves: //' \
        | sort -u \
        | grep -v '^$' \
        || true
)

if [[ -z "$issue_urls" ]]; then
    echo "No issues found in commits from $FROM to $TO" >&2
    exit 0
fi

# Process each issue
for url in $issue_urls; do
    # Extract issue number from URL
    issue_number=$(echo "$url" | grep -oE '[0-9]+$')

    # Get issue details using gh
    issue_json=$(
        gh issue view "$issue_number" --json number,title,state 2>/dev/null || echo ""
    )

    if [[ -z "$issue_json" ]]; then
        echo "Warning: Could not fetch issue #$issue_number" >&2
        continue
    fi

    # Parse JSON with jq
    state=$(echo "$issue_json" | jq -r '.state')
    title=$(echo "$issue_json" | jq -r '.title')

    # Only include closed issues
    if [[ "$state" != "CLOSED" ]]; then
        continue
    fi

    # Output based on format
    case "$FORMAT" in
        plain)
            echo "* #$issue_number $url - $title"
            ;;
        md)
            echo "* [#$issue_number]($url) - $title"
            ;;
        rst)
            echo "* \`#$issue_number <$url>\`__ - $title"
            ;;
    esac
done
