#!/bin/sh

mkdir -p build

# Check falafel version.
falafelVersion=$1
if [ -z $falafelVersion ]
then
        echo "falafel version not set"
        exit 1
fi

falafel=$(which falafel)
if [ $falafel ]
then
        version="v$($falafel -v)"
        if [ $version != $falafelVersion ]
        then
                echo "falafel version $falafelVersion required, had $version"
                exit 1
        fi
        echo "Using plugin $falafel $version"
else
        echo "falafel not found"
        exit 1
fi

# Name of the package for the generated APIs.
pkg="lndmobile"

# The package where the protobuf definitions originally are found.
target_pkg="github.com/lightningnetwork/lnd/lnrpc"

# A mapping from grpc service to name of the custom listeners. The grpc server
# must be configured to listen on these.
listeners="lightning=lightningLis walletunlocker=lightningLis state=lightningLis"

# Set to 1 to create boiler plate grpc client code and listeners. If more than
# one proto file is being parsed, it should only be done once.
mem_rpc=1

PROTOS="lightning.proto walletunlocker.proto stateservice.proto"

opts="package_name=$pkg,target_package=$target_pkg,listeners=$listeners,mem_rpc=$mem_rpc"

for file in $PROTOS; do
  echo "Generating mobile protos from ${file}"

  protoc -I/usr/local/include -I. \
         --plugin=protoc-gen-custom=$falafel\
         --custom_out=./build \
         --custom_opt="$opts" \
         --proto_path=../lnrpc \
         "${file}"
done

# If prefix=1 is specified, prefix the generated methods with subserver name.
# This must be enabled to support subservers with name conflicts.
use_prefix="0"
if [ "$SUBSERVER_PREFIX" = "1" ]
then
    echo "Prefixing methods with subserver name"
    use_prefix="1"
fi

# Find all subservers.
for file in ../lnrpc/**/*.proto
do
    DIRECTORY=$(dirname ${file})
    tag=$(basename ${DIRECTORY})
    build_tags="// +build $tag"
    lis="lightningLis"

    opts="package_name=$pkg,target_package=$target_pkg/$tag,build_tags=$build_tags,api_prefix=$use_prefix,defaultlistener=$lis"

    echo "Generating mobile protos from ${file}, with build tag ${tag}"

    protoc -I/usr/local/include -I. \
           -I../lnrpc \
           --plugin=protoc-gen-custom=$falafel \
           --custom_out=./build \
           --custom_opt="$opts" \
           --proto_path=${DIRECTORY} \
           ${file}
done

# Run goimports to resolve any dependencies among the sub-servers.
goimports -w ./*_generated.go
