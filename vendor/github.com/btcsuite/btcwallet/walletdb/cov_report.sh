#!/bin/sh

# This script uses go tool cover to generate a test coverage report.
go test -coverprofile=cov.out && go tool cover -func=cov.out && rm -f cov.out
echo "============================================================"
(cd bdb && go test -coverprofile=cov.out && go tool cover -func=cov.out && \
  rm -f cov.out)
