#!/bin/bash

set -e

WALLET_SECRET_NAME=${WALLET_SECRET_NAME:-lnd-wallet-secret}
WALLET_DIR=${WALLET_DIR:-~/.lnd/data/chain/bitcoin/mainnet}
WALLET_PASSWORD_FILE=${WALLET_PASSWORD_FILE:-/tmp/wallet-password}
CERT_DIR=${CERT_DIR:-~/.lnd}
UPLOAD_RPC_SECRETS=${UPLOAD_RPC_SECRETS:-0}
RPC_SECRETS_NAME=${RPC_SECRETS_NAME:-lnd-rpc-secret}

echo "[STARTUP] Asserting wallet password exists in secret ${WALLET_SECRET_NAME}"
lndinit gen-password \
  | lndinit -v store-secret \
  --target=k8s \
  --k8s.secret-name="${WALLET_SECRET_NAME}" \
  --k8s.secret-entry-name=wallet-password

echo ""
echo "[STARTUP] Asserting seed exists in secret ${WALLET_SECRET_NAME}"
lndinit gen-seed \
  | lndinit -v store-secret \
  --target=k8s \
  --k8s.secret-name="${WALLET_SECRET_NAME}" \
  --k8s.secret-entry-name=seed

echo ""
echo "[STARTUP] Asserting wallet is created with values from secret ${WALLET_SECRET_NAME}"
lndinit -v init-wallet \
  --secret-source=k8s \
  --k8s.secret-name="${WALLET_SECRET_NAME}" \
  --k8s.seed-entry-name=seed \
  --k8s.wallet-password-entry-name=wallet-password \
  --output-wallet-dir="${WALLET_DIR}" \
  --validate-password

echo ""
echo "[STARTUP] Preparing lnd auto unlock file"

# To make sure the password can be read exactly once (by lnd itself), we create
# a named pipe. Because we can only write to such a pipe if there's a reader on
# the other end, we need to run this in a sub process in the background.
mkfifo "${WALLET_PASSWORD_FILE}"
lndinit -v load-secret \
  --source=k8s \
  --k8s.secret-name="${WALLET_SECRET_NAME}" \
  --k8s.secret-entry-name=wallet-password > "${WALLET_PASSWORD_FILE}" &

# In case we want to upload the TLS certificate and macaroons to k8s secrets as
# well once lnd is ready, we can use the wait-ready and store-secret commands in
# combination to wait until lnd is ready and then batch upload the files to k8s.
if [[ "${UPLOAD_RPC_SECRETS}" == "1" ]]; then
  echo ""
  echo "[STARTUP] Starting RPC secret uploader process in background"
  lndinit -v wait-ready \
    && lndinit -v store-secret \
    --batch \
    --overwrite \
    --target=k8s \
    --k8s.secret-name="${RPC_SECRETS_NAME}" \
    "${CERT_DIR}/tls.cert" \
    "${WALLET_DIR}"/*.macaroon &
fi

# And finally start lnd. We need to use "exec" here to make sure all signals are
# forwarded correctly.
echo ""
echo "[STARTUP] Starting lnd with flags: $@"
exec lnd "$@"
