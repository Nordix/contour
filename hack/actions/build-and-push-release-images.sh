#! /usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

# This scripts sets TAG_LATEST based on whether the tag currently being
# built is the highest semantic version tag that's not a pre-release
# (alpha, beta, rc), and calls 'make push'.
#
# This script is intended to be run only for tag builds and will no-op
# if GITHUB_REF is not in the format "refs/tags/<tag-name>".

# Check if the current build is for a tag and exit early if not.
REF_TYPE=$(echo "$GITHUB_REF" | cut -d / -f 2)
if [[ "$REF_TYPE" != "tags" ]]; then
    echo "REF_TYPE $REF_TYPE is not a tag, exiting."
    exit 0
fi

# Get the current tag name.
CURRENT_TAG=$(echo "$GITHUB_REF" | cut -d / -f 3)
if [[ -z "$CURRENT_TAG" ]]; then
    echo "Error getting current tag name from GITHUB_REF $GITHUB_REF."
    exit 1
fi

# Fetch all tags so we can check if the current tag
# is the highest semver.
git fetch --tags

HIGHEST_SEMVER_TAG=""

# The --sort=-v:refname flag treats tag names as versions, so gives
# us semantic sorting rather than lexicographic (alphabetic) sorting.
for t in $(git tag -l --sort=-v:refname); do
    # Skip pre-release tags
    if [[ "$t" == *"beta"* || "$t" == *"alpha"* || "$t" == *"rc"* ]]; then
        continue
    fi
    HIGHEST_SEMVER_TAG="$t"
    break
done

echo "CURRENT_TAG: $CURRENT_TAG"
echo "HIGHEST_SEMVER_TAG: $HIGHEST_SEMVER_TAG"

TAG_LATEST="false"
if [[ "$CURRENT_TAG" != "$HIGHEST_SEMVER_TAG" ]]; then
    echo "Current tag is not the highest semver tag, image will not be tagged as 'latest'."
else
    echo "Current tag is the highest semver tag, image will also be tagged as 'latest'."
    TAG_LATEST="true"
fi

make push TAG_LATEST="$TAG_LATEST"