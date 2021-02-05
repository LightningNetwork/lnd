FROM lnd-go-base:latest

MAINTAINER Olaoluwa Osuntokun <laolu@lightning.engineering>

# Set up cache directories. Those will be mounted from the host system to speed
# up builds. If go isn't installed on the host system, those will fall back to
# temp directories during the build (see make/release_flags.mk).
ENV GOCACHE=/tmp/build/.cache
ENV GOMODCACHE=/tmp/build/.modcache

RUN apk add --no-cache --update alpine-sdk \
    git \
    make \
    tar \
    zip \
    bash \
  && mkdir -p /tmp/build/lnd \
  && mkdir -p /tmp/build/.cache \
  && mkdir -p /tmp/build/.modcache \
  && chmod -R 777 /tmp/build/

WORKDIR /tmp/build/lnd
