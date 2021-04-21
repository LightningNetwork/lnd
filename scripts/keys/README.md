# Release verification keys

This directory contains all keys that are currently signing `lnd` releases.

The name of the file must match exactly the suffix that user is going to use
when signing a release.
For example, if the key is called `eugene_.asc` then that user must upload a
signature file called `manifest-eugene_-v0.xx.yy-beta.sig`, otherwise the
verification will fail.

In addition to adding the key file here as a `.asc` file the
`scripts/verify-install.sh` file must also be updated with the key ID and the
reference to the key file.
