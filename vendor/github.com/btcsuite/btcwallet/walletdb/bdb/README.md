bdb
===

[![Build Status](https://travis-ci.org/btcsuite/btcwallet.png?branch=master)]
(https://travis-ci.org/btcsuite/btcwallet)

Package bdb implements an driver for walletdb that uses boltdb for the backing
datastore.  Package bdb is licensed under the copyfree ISC license.

## Usage

This package is only a driver to the walletdb package and provides the database
type of "bdb". The only parameters the Open and Create functions take is the
database path as a string, and an option for the database to not sync its
freelist to disk as a bool:

```Go
db, err := walletdb.Open("bdb", "path/to/database.db", true)
if err != nil {
	// Handle error
}
```

```Go
db, err := walletdb.Create("bdb", "path/to/database.db", true)
if err != nil {
	// Handle error
}
```

## Documentation

[![GoDoc](https://godoc.org/github.com/btcsuite/btcwallet/walletdb/bdb?status.png)]
(http://godoc.org/github.com/btcsuite/btcwallet/walletdb/bdb)

Full `go doc` style documentation for the project can be viewed online without
installing this package by using the GoDoc site here:
http://godoc.org/github.com/btcsuite/btcwallet/walletdb/bdb

You can also view the documentation locally once the package is installed with
the `godoc` tool by running `godoc -http=":6060"` and pointing your browser to
http://localhost:6060/pkg/github.com/btcsuite/btcwallet/walletdb/bdb

## License

Package bdb is licensed under the [copyfree](http://copyfree.org) ISC
License.
