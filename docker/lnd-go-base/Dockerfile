# If you change this value, please change it in the following files as well:
# /.travis.yml
# /.github/workflows/main.yml
# /.github/workflows/release.yml
FROM golang:1.15.7-alpine

MAINTAINER Olaoluwa Osuntokun <laolu@lightning.engineering>

# Golang build related environment variables that are static and used for all
# architectures/OSes.

# Force Go to use the cgo based DNS resolver. This is required to ensure DNS
# queries required to connect to linked containers succeed.
ENV GODEBUG netdns=cgo

ENV GO111MODULE=auto
ENV CGO_ENABLED=0
