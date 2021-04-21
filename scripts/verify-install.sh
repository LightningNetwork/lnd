#!/bin/bash

REPO=lightningnetwork
PROJECT=lnd

RELEASE_URL=https://github.com/$REPO/$PROJECT/releases
API_URL=https://api.github.com/repos/$REPO/$PROJECT/releases
MANIFEST_SELECTOR=". | select(.name | test(\"manifest-v.*(\\\\.txt)$\")) | .name"
SIGNATURE_SELECTOR=". | select(.name | test(\"manifest-.*(\\\\.sig)$\")) | .name"
HEADER_JSON="Accept: application/json"
HEADER_GH_JSON="Accept: application/vnd.github.v3+json"
MIN_REQUIRED_SIGNATURES=5

# All keys that can sign lnd releases. The key must be added as a file to the
# keys directory, for example: scripts/keys/<username>.asc
# The username in the key file must match the username used for signing a
# manifest (manifest-<username>-v0.xx.yy-beta.sig), otherwise the signature
# won't be counted.
# NOTE: Reviewers of this file must make sure that both the key IDs and
# usernames in the list below are unique!
KEYS=()
KEYS+=("F4FC70F07310028424EFC20A8E4256593F177720 guggero")
KEYS+=("15E7ECF257098A4EF91655EB4CA7FE54A6213C91 carlaKC")
KEYS+=("9C8D61868A7C492003B2744EE7D737B67FA592C7 cfromknecht")
KEYS+=("E4D85299674B2D31FAA1892E372CBD7633C61696 roasbeef")
KEYS+=("729E9D9D92C75A5FBFEEE057B5DD717BEF7CA5B1 wpaulino")
KEYS+=("7E81EF6B9989A9CC93884803118759E83439A9B1 Crypt-iQ")
KEYS+=("7AB3D7F5911708842796513415BAADA29DA20D26 halseth")
KEYS+=("9FC6B0BFD597A94DBF09708280E5375C094198D8 bhandras")

TEMP_DIR=$(mktemp -d /tmp/lnd-sig-verification-XXXXXX)

function check_command() {
  echo -n "Checking if $1 is installed... "
  if ! command -v "$1"; then
    echo "ERROR: $1 is not installed or not in PATH!"
    exit 1
  fi
}

function verify_version() {
  version_regex="^v[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]"
  if [[ ! "$1" =~ $version_regex ]]; then
    echo "ERROR: Invalid expected version detected: $1"
    exit 1
  fi
  echo "Expected version for binaries: $1"
}

function import_keys() {
  # A trick to get the absolute directory where this script is located, no
  # matter how or from where it was called. We'll need it to locate the key
  # files which are located relative to this script.
  DIR="$(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"

  # Import all the signing keys. We'll create a key ring for each user and use
  # that exact key ring when verifying a user's signature. That way we can make
  # sure one user cannot just upload multiple signatures to reach the 5/7
  # required sigs.
  for key in "${KEYS[@]}"; do
    KEY_ID=$(echo $key | cut -d' ' -f1)
    USERNAME=$(echo $key | cut -d' ' -f2)
    IMPORT_FILE="keys/$USERNAME.asc"
    KEY_FILE="$DIR/$IMPORT_FILE"
    KEYRING_UNTRUSTED="$TEMP_DIR/$USERNAME.pgp-untrusted"
    KEYRING_TRUSTED="$TEMP_DIR/$USERNAME.pgp"

    # Because a key file could contain multiple keys, we need to be careful. To
    # make sure we only import and use the key with the hard coded key ID of
    # this script, we first import the file into a temporary untrusted keyring
    # and then only export the specific key with the given ID into our final,
    # trusted keyring that we later use for verification. This is exactly what
    # https://github.com/Kixunil/sqck does but we didn't want to add another
    # binary dependency to this script so we re-implemented it in the following
    # few lines.
    echo ""
    echo "Importing key(s) from $KEY_FILE into temporary keyring $KEYRING_UNTRUSTED"
    gpg --no-default-keyring --keyring "$KEYRING_UNTRUSTED" \
      --import < "$KEY_FILE"

    echo ""
    echo "Exporting key $KEY_ID from untrusted keyring to trusted keyring $KEYRING_TRUSTED"
    gpg --no-default-keyring --keyring "$KEYRING_UNTRUSTED" \
      --export "$KEY_ID" | \
      gpg --no-default-keyring --keyring "$KEYRING_TRUSTED" --import

  done
}

function verify_signatures() {
  # Download the JSON of the release itself. That'll contain the release ID we
  # need for the next call.
  RELEASE_JSON=$(curl -L -s -H "$HEADER_JSON" "$RELEASE_URL/$VERSION")

  TAG_NAME=$(echo $RELEASE_JSON | jq -r '.tag_name')
  RELEASE_ID=$(echo $RELEASE_JSON | jq -r '.id')
  echo "Release $TAG_NAME found with ID $RELEASE_ID"

  # Now download the asset list and filter by the manifest and the signatures.
  ASSETS=$(curl -L -s -H "$HEADER_GH_JSON" "$API_URL/$RELEASE_ID" | jq -c '.assets[]')
  MANIFEST=$(echo $ASSETS | jq -r "$MANIFEST_SELECTOR")
  SIGNATURES=$(echo $ASSETS | jq -r "$SIGNATURE_SELECTOR")

  # Download the main "manifest-*.txt" and all "manifest-*.sig" files containing
  # the detached signatures.
  echo "Downloading $MANIFEST"
  curl -L -s -o "$TEMP_DIR/$MANIFEST" "$RELEASE_URL/download/$VERSION/$MANIFEST"

  for signature in $SIGNATURES; do
    echo "Downloading $signature"
    curl -L -s -o "$TEMP_DIR/$signature" "$RELEASE_URL/download/$VERSION/$signature"
  done

  echo ""

  # Before we even look at the content of the manifest, we first want to make
  # sure the signatures actually sign that exact manifest.
  NUM_CHECKS=0
  for signature in $SIGNATURES; do
    echo "Verifying $signature"
    if gpg --verify "$TEMP_DIR/$signature" "$TEMP_DIR/$MANIFEST" 2>&1 | grep -q "Good signature"; then
      echo "Signature for $signature appears valid: "
      gpg --verify "$TEMP_DIR/$signature" "$TEMP_DIR/$MANIFEST" 2>&1 | grep "using"
    elif gpg --verify "$TEMP_DIR/$signature" 2>&1 | grep -q "No public key"; then
      echo "Unable to verify signature $signature, no key available, skipping"
      continue
    else
      echo "ERROR: Did not get valid signature for $MANIFEST in $signature!"
      echo "  The developer signature $signature disagrees on the expected"
      echo "  release binaries in $MANIFEST. The release may have been faulty or"
      echo "  was backdoored."
      exit 1
    fi

    echo "Verified $signature against $MANIFEST"
    ((NUM_CHECKS=NUM_CHECKS+1))
  done

  # We want at least five signatures (out of seven public keys) that sign the
  # hashes of the binaries we have installed. If we arrive here without exiting,
  # it means no signature manifests were uploaded (yet) with the correct naming
  # pattern.
  if [[ $NUM_CHECKS -lt $MIN_REQUIRED_SIGNATURES ]]; then
    echo "ERROR: Not enough valid signatures found!"
    echo "  Valid signatures found: $NUM_CHECKS"
    echo "  Valid signatures required: $MIN_REQUIRED_SIGNATURES"
    echo
    echo "  Make sure the release $VERSION contains the required "
    echo "  number of signatures on the manifest, or wait until more "
    echo "  signatures have been added to the release."
    exit 1
  fi
}

function check_hash() {
  # Make this script compatible with both linux and *nix.
  SHA_CMD="sha256sum"
  if ! command -v "$SHA_CMD" > /dev/null; then
    if command -v "shasum"; then
      SHA_CMD="shasum -a 256"
    else
      echo "ERROR: no SHA256 sum binary installed!"
      exit 1
    fi
  fi
  SUM=$($SHA_CMD "$1" | cut -d' ' -f1)

  # Make sure the hash was actually calculated by looking at its length.
  if [[ ${#SUM} -ne 64 ]]; then
    echo "ERROR: Invalid hash for $2: $SUM!"
    exit 1
  fi

  echo "Verifying $1 as version $VERSION with SHA256 sum $SUM"

  # If we're inside the docker image, there should be a shasums.txt file in the
  # root directory. If that's the case, we first want to make sure we still have
  # the same hash as we did when building the image.
  if [[ -f /shasums.txt ]]; then
    if ! grep -q "$SUM" /shasums.txt; then
      echo "ERROR: Hash $SUM for $2 not found in /shasums.txt: "
      cat /shasums.txt
      exit 1
    fi
  fi

  if ! grep -q "^$SUM" "$TEMP_DIR/$MANIFEST"; then
    echo "ERROR: Hash $SUM for $2 not found in $MANIFEST: "
    cat "$TEMP_DIR/$MANIFEST"
    echo "  The expected release binaries have been verified with the developer "
    echo "  signatures. Your binary's hash does not match the expected release "
    echo "  binary hashes. Make sure you're using an official binary."
    exit 1
  fi
}

# By default we're picking up lnd and lncli from the system $PATH.
LND_BIN=$(which lnd)
LNCLI_BIN=$(which lncli)

if [[ $# -eq 0 ]]; then
  echo "ERROR: missing expected version!"
  echo "Usage: verify-install.sh expected-version [path-to-lnd-binary path-to-lncli-binary]"
  exit 1
fi

# The first argument should be the expected version of the binaries.
VERSION=$1
shift

# Verify that the expected version is well-formed.
verify_version "$VERSION"

# If exactly two parameters are specified, we expect the first one to be lnd and
# the second one to be lncli.
if [[ $# -eq 2 ]]; then
  LND_BIN=$(realpath $1)
  LNCLI_BIN=$(realpath $2)
  
  # Make sure both files actually exist.
  if [[ ! -f $LND_BIN ]]; then
    echo "ERROR: $LND_BIN not found!"
    exit 1
  fi
  if [[ ! -f $LNCLI_BIN ]]; then
    echo "ERROR: $LNCLI_BIN not found!"
    exit 1
  fi
elif [[ $# -eq 0 ]]; then
  # By default we're picking up lnd and lncli from the system $PATH.
  LND_BIN=$(which lnd)
  LNCLI_BIN=$(which lncli)
else
  echo "ERROR: invalid number of parameters!"
  echo "Usage: verify-install.sh [lnd-binary lncli-binary]"
  exit 1
fi

# Make sure both binaries can be found and are executable.
check_command "$LND_BIN"
check_command "$LNCLI_BIN"

check_command curl
check_command jq
check_command gpg

# Import all the signing keys.
import_keys

echo ""

# Verify and count the signatures.
verify_signatures

# Then make sure that the hash of the installed binaries can be found in the
# manifest that we now have verified the signatures for.
check_hash "$LND_BIN" "lnd"
check_hash "$LNCLI_BIN" "lncli"

echo ""
echo "SUCCESS! Verified lnd and lncli against $MANIFEST signed by $NUM_CHECKS developers."
