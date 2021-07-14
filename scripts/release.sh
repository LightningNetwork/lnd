#!/bin/bash

# Simple bash script to build basic lnd tools for all the platforms
# we support with the golang cross-compiler.
#
# Copyright (c) 2016 Company 0, LLC.
# Use of this source code is governed by the ISC
# license.

set -e

LND_VERSION_REGEX="lnd version (.+) commit"
PKG="github.com/lightningnetwork/lnd"
PACKAGE=lnd

# Needed for setting file timestamps to get reproducible archives.
BUILD_DATE="2020-01-01 00:00:00"
BUILD_DATE_STAMP="202001010000.00"

# reproducible_tar_gzip creates a reproducible tar.gz file of a directory. This
# includes setting all file timestamps and ownership settings uniformly.
function reproducible_tar_gzip() {
  local dir=$1
  local tar_cmd=tar

  # MacOS has a version of BSD tar which doesn't support setting the --mtime
  # flag. We need gnu-tar, or gtar for short to be installed for this script to
  # work properly.
  tar_version=$(tar --version)
  if [[ ! "$tar_version" =~ "GNU tar" ]]; then
    if ! command -v "gtar"; then
      echo "GNU tar is required but cannot be found!"
      echo "On MacOS please run 'brew install gnu-tar' to install gtar."
      exit 1
    fi

    # We have gtar installed, use that instead.
    tar_cmd=gtar
  fi

  # Pin down the timestamp time zone.
  export TZ=UTC

  find "${dir}" -print0 | LC_ALL=C sort -r -z | $tar_cmd \
    "--mtime=${BUILD_DATE}" --no-recursion --null --mode=u+rw,go+r-w,a+X \
    --owner=0 --group=0 --numeric-owner -c -T - | gzip -9n > "${dir}.tar.gz"

  rm -r "${dir}"
}

# reproducible_zip creates a reproducible zip file of a directory. This
# includes setting all file timestamps.
function reproducible_zip() {
  local dir=$1

  # Pin down file name encoding and timestamp time zone.
  export TZ=UTC

  # Set the date of each file in the directory that's about to be packaged to
  # the same timestamp and make sure the same permissions are used everywhere.
  chmod -R 0755 "${dir}"
  touch -t "${BUILD_DATE_STAMP}" "${dir}"
  find "${dir}" -print0 | LC_ALL=C sort -r -z | xargs -0r touch \
    -t "${BUILD_DATE_STAMP}"

  find "${dir}" | LC_ALL=C sort -r | zip -o -X -r -@ "${dir}.zip"

  rm -r "${dir}"
}

# green prints one line of green text (if the terminal supports it).
function green() {
  echo -e "\e[0;32m${1}\e[0m"
}

# red prints one line of red text (if the terminal supports it).
function red() {
  echo -e "\e[0;31m${1}\e[0m"
}

# check_tag_correct makes sure the given git tag is checked out and the git tree
# is not dirty.
#   arguments: <version-tag>
function check_tag_correct() {
  local tag=$1

  # For automated builds we can skip this check as they will only be triggered
  # on tags.
  if [[ "$SKIP_VERSION_CHECK" -eq "1" ]]; then
    green "skipping version check, assuming automated build"
    exit 0
  fi

  # If a tag is specified, ensure that that tag is present and checked out.
  if [[ $tag != $(git describe --tags) ]]; then
    red "tag $tag not checked out"
    exit 1
  fi

  # Build lnd to extract version.
  go build ${PKG}/cmd/lnd

  # Extract version command output.
  lnd_version_output=$(./lnd --version)

  # Use a regex to isolate the version string.
  if [[ $lnd_version_output =~ $LND_VERSION_REGEX ]]; then
    # Prepend 'v' to match git tag naming scheme.
    lnd_version="v${BASH_REMATCH[1]}"
    green "version: $lnd_version"

    # If tag contains a release candidate suffix, append this suffix to the
    # lnd reported version before we compare.
    RC_REGEX="-rc[0-9]+$"
    if [[ $tag =~ $RC_REGEX ]]; then
      lnd_version+=${BASH_REMATCH[0]}
    fi

    # Match git tag with lnd version.
    if [[ $tag != "${lnd_version}" ]]; then
      red "lnd version $lnd_version does not match tag $tag"
      exit 1
    fi
  else
    red "malformed lnd version output"
    exit 1
  fi
}

# build_release builds the actual release binaries.
#   arguments: <version-tag> <build-system(s)> <build-tags> <ldflags>
function build_release() {
  local tag=$1
  local sys=$2
  local buildtags=$3
  local ldflags=$4

  green " - Packaging vendor"
  go mod vendor
  reproducible_tar_gzip vendor

  rootdir=$(pwd)
  maindir=$PACKAGE-$tag
  mkdir -p $maindir
  mv vendor.tar.gz "${maindir}/"

  # Don't use tag in source directory, otherwise our file names get too long and
  # tar starts to package them non-deterministically.
  package_source="${PACKAGE}-source"

  # The git archive command doesn't support setting timestamps and file
  # permissions. That's why we unpack the tar again, then use our reproducible
  # method to create the final archive.
  git archive -o "${maindir}/${package_source}.tar" HEAD

  cd "${maindir}"
  mkdir -p ${package_source}
  tar -xf "${package_source}.tar" -C ${package_source}
  rm "${package_source}.tar"
  reproducible_tar_gzip ${package_source}
  mv "${package_source}.tar.gz" "${package_source}-$tag.tar.gz" 

  for i in $sys; do
    os=$(echo $i | cut -f1 -d-)
    arch=$(echo $i | cut -f2 -d-)
    arm=

    if [[ $arch == "armv6" ]]; then
      arch=arm
      arm=6
    elif [[ $arch == "armv7" ]]; then
      arch=arm
      arm=7
    fi

    dir="${PACKAGE}-${i}-${tag}"
    mkdir "${dir}"
    pushd "${dir}"

    green " - Building: ${os} ${arch} ${arm} with build tags '${buildtags}'"
    env CGO_ENABLED=0 GOOS=$os GOARCH=$arch GOARM=$arm go build -v -trimpath -ldflags="${ldflags}" -tags="${buildtags}" ${PKG}/cmd/lnd
    env CGO_ENABLED=0 GOOS=$os GOARCH=$arch GOARM=$arm go build -v -trimpath -ldflags="${ldflags}" -tags="${buildtags}" ${PKG}/cmd/lncli

    # The lndinit binary needs to be built a bit differently because it is its
    # own submodule.
    pushd ../../cmd/lndinit
    env CGO_ENABLED=0 GOOS=$os GOARCH=$arch GOARM=$arm go build -v -trimpath -ldflags="${ldflags}" -tags="${buildtags}" -o "${rootdir}/${maindir}/${dir}" .
    popd

    popd

    # Add the hashes for the individual binaries as well for easy verification
    # of a single installed binary.
    shasum -a 256 "${dir}/"* >> "manifest-$tag.txt" 

    if [[ $os == "windows" ]]; then
      reproducible_zip "${dir}"
    else
      reproducible_tar_gzip "${dir}"
    fi
  done

  # Add the hash of the packages too, then sort by the second column (name).
  shasum -a 256 lnd-* vendor* >> "manifest-$tag.txt"
  LC_ALL=C sort -k2 -o "manifest-$tag.txt" "manifest-$tag.txt"
  cat "manifest-$tag.txt"
}

# usage prints the usage of the whole script.
function usage() {
  red "Usage: "
  red "release.sh check-tag <version-tag>"
  red "release.sh build-release <version-tag> <build-system(s)> <build-tags> <ldflags>"
}

# Whatever sub command is passed in, we need at least 2 arguments.
if [ "$#" -lt 2 ]; then
  usage
  exit 1
fi

# Extract the sub command and remove it from the list of parameters by shifting
# them to the left.
SUBCOMMAND=$1
shift

# Call the function corresponding to the specified sub command or print the
# usage if the sub command was not found.
case $SUBCOMMAND in
check-tag)
  green "Checking if version tag exists"
  check_tag_correct "$@"
  ;;
build-release)
  green "Building release"
  build_release "$@"
  ;;
*)
  usage
  exit 1
  ;;
esac
