# Release Notes

# Misc

* The direct use of certain syscalls in packages such as `bbolt` or `lnd`'s own
  `healthcheck` package made it impossible to import `lnd` code as a library
  into projects that are compiled to WASM binaries. [That problem was fixed by
  guarding those syscalls with build tags](https://github.com/lightningnetwork/lnd/pull/5526).

# Contributors (Alphabetical Order)
Oliver Gugger