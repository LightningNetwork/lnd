#!/bin/bash

set -e

# generate compiles the *.pb.go stubs from the *.proto files.
function generate() {
  echo "Generating root gRPC server protos"
  
  PROTOS="rpc.proto walletunlocker.proto **/*.proto"
  
  # For each of the sub-servers, we then generate their protos, but a restricted
  # set as they don't yet require REST proxies, or swagger docs.
  for file in $PROTOS; do
    DIRECTORY=$(dirname "${file}")
    echo "Generating protos from ${file}, into ${DIRECTORY}"
  
    # Generate the protos.
    protoc \
      --go_out=plugins=grpc,paths=source_relative:. \
      "${file}"
  
    # Generate the REST reverse proxy.
    protoc \
      --grpc-gateway_out=logtostderr=true,paths=source_relative,grpc_api_configuration=rest-annotations.yaml:. \
      "${file}"
  
  
    # Finally, generate the swagger file which describes the REST API in detail.
    protoc \
      --swagger_out=logtostderr=true,grpc_api_configuration=rest-annotations.yaml:. \
      "${file}"
  done
}

# format formats the *.proto files with the clang-format utility.
function format() {
  find . -name "*.proto" -print0 | xargs -0 clang-format --style=file -i
}

# Compile and format the lnrpc package.
pushd lnrpc
format
generate
popd

if [[ "$COMPILE_MOBILE" == "1" ]]; then
  pushd mobile
  ./gen_bindings.sh $FALAFEL_VERSION
  popd
fi
