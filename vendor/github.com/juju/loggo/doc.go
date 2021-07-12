// Copyright 2014 Canonical Ltd.
// Licensed under the LGPLv3, see LICENCE file for details.

/*
[godoc-link-here]

Module level logging for Go

This package provides an alternative to the standard library log package.

The actual logging functions never return errors.  If you are logging
something, you really don't want to be worried about the logging
having trouble.

Modules have names that are defined by dotted strings.
	"first.second.third"

There is a root module that has the name `""`.  Each module
(except the root module) has a parent, identified by the part of
the name without the last dotted value.
* the parent of "first.second.third" is "first.second"
* the parent of "first.second" is "first"
* the parent of "first" is "" (the root module)

Each module can specify its own severity level.  Logging calls that are of
a lower severity than the module's effective severity level are not written
out.

Loggers are created through their Context. There is a default global context
that is used if you just want simple use. Contexts are used where you may want
different sets of writers for different loggers. Most use cases are fine with
just using the default global context.

Loggers are created using the GetLogger function.
	logger := loggo.GetLogger("foo.bar")

The default global context has one writer registered, which will write to Stderr,
and the root module, which will only emit warnings and above.
If you want to continue using the default
logger, but have it emit all logging levels you need to do the following.

	writer, err := loggo.RemoveWriter("default")
	// err is non-nil if and only if the name isn't found.
	loggo.RegisterWriter("default", writer)

To make loggo produce colored output, you can do the following,
having imported github.com/juju/loggo/loggocolor:

	loggo.ReplaceDefaultWriter(loggocolor.NewWriter(os.Stderr))
*/
package loggo
