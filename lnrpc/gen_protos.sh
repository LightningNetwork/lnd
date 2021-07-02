#!/bin/bash

set -e

# generate compiles the *.pb.go stubs from the *.proto files.
function generate() {
  echo "Generating root gRPC server protos"
  
  PROTOS="rpc.proto walletunlocker.proto stateservice.proto **/*.proto"
  
  # For each of the sub-servers, we then generate their protos, but a restricted
  # set as they don't yet require REST proxies, or swagger docs.
  for file in $PROTOS; do
    DIRECTORY=$(dirname "${file}")
    echo "Generating protos from ${file}, into ${DIRECTORY}"
  
    # Generate the protos.
    protoc -I/usr/local/include -I. \
      --go_out=plugins=grpc,paths=source_relative:. \
      "${file}"
  
    # Generate the REST reverse proxy.
    annotationsFile=${file//proto/yaml}
    protoc -I/usr/local/include -I. \
      --grpc-gateway_out=logtostderr=true,paths=source_relative,grpc_api_configuration=${annotationsFile}:. \
      "${file}"
  
  
    # Finally, generate the swagger file which describes the REST API in detail.
    protoc -I/usr/local/include -I. \
      --swagger_out=logtostderr=true,grpc_api_configuration=${annotationsFile}:. \
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
