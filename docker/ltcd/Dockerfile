FROM lnd-go-base:latest as builder

LABEL maintainer="Olaoluwa Osuntokun <laolu@lightning.engineering>"

# Grab and install the latest version of roasbeef's fork of ltcd and all
# related dependencies.
WORKDIR $GOPATH/src/github.com/ltcsuite/ltcd
RUN apk add --no-cache --update alpine-sdk git
RUN git clone https://github.com/ltcsuite/ltcd ./
RUN GO111MODULE=on go install -v . ./cmd/...
RUN GO111MODULE=on go install . ./cmd/ltcctl ./cmd/gencerts

# Start a new image
FROM alpine as final

# Expose mainnet ports (server, rpc)
EXPOSE 9333 9334

# Expose testnet ports (server, rpc)
EXPOSE 19334 19335

# Expose simnet ports (server, rpc)
EXPOSE 18555 18556

# Copy the compiled binaries from the builder image.
COPY --from=builder /go/bin/ltcctl /bin/
COPY --from=builder /go/bin/ltcd /bin/
COPY --from=builder /go/bin/gencerts /bin/

COPY "start-ltcctl.sh" .
COPY "start-ltcd.sh" .

RUN apk add --no-cache \
    bash \
    ca-certificates \
&&  chmod +x start-ltcctl.sh \
&&  chmod +x start-ltcd.sh \
&&  mkdir "/rpc" "/root/.ltcd" "/root/.ltcctl" \
&&  touch "/root/.ltcd/ltcd.conf" \
# "ltcctl" and "lnd" to "ltcd" over docker links.
&&  "/bin/gencerts" --host="*" --directory="/rpc" --force

# Create a volume to house pregenerated RPC credentials. This will be
# shared with any lnd, btcctl containers so they can securely query ltcd's RPC
# server.
# You should NOT do this before certificate generation!
# Otherwise manually generated certificate will be overridden with shared
# mounted volume! For more info read dockerfile "VOLUME" documentation.
VOLUME ["/rpc"]
