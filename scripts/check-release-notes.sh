#!/bin/bash

set -e

# Extract the PR number which is stored in the $GITHUB_REF env variable. The
# format of the string stored in the variable is: refs/pull/:PRNUMBER/merge.
PR_NUMBER=$(echo $GITHUB_REF | awk 'BEGIN { FS = "/" } ; { print $3 }')

# Ensure that the PR number at least shows up in the release notes folder under
# one of the contained milestones.
if ! grep -r -q "lightningnetwork/lnd/pull/$PR_NUMBER" docs/release-notes; then
    echo "PR $PR_NUMBER didn't update release notes"
    exit 1
fi
