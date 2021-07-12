// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package btclog defines an interface and default implementation for subsystem
logging.

Log level verbosity may be modified at runtime for each individual subsystem
logger.

The default implementation in this package must be created by the Backend type.
Backends can write to any io.Writer, including multi-writers created by
io.MultiWriter.  Multi-writers allow log output to be written to many writers,
including standard output and log files.

Optional logging behavior can be specified by using the LOGFLAGS environment
variable and overridden per-Backend by using the WithFlags call option. Multiple
LOGFLAGS options can be specified, separated by commas.  The following options
are recognized:

  longfile: Include the full filepath and line number in all log messages

  shortfile: Include the filename and line number in all log messages.
  Overrides longfile.
*/
package btclog
