// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package btcjson provides primitives for working with the bitcoin JSON-RPC API.

Overview

When communicating via the JSON-RPC protocol, all of the commands need to be
marshalled to and from the the wire in the appropriate format.  This package
provides data structures and primitives to ease this process.

In addition, it also provides some additional features such as custom command
registration, command categorization, and reflection-based help generation.

JSON-RPC Protocol Overview

This information is not necessary in order to use this package, but it does
provide some intuition into what the marshalling and unmarshalling that is
discussed below is doing under the hood.

As defined by the JSON-RPC spec, there are effectively two forms of messages on
the wire:

  - Request Objects
    {"jsonrpc":"1.0","id":"SOMEID","method":"SOMEMETHOD","params":[SOMEPARAMS]}
    NOTE: Notifications are the same format except the id field is null.

  - Response Objects
    {"result":SOMETHING,"error":null,"id":"SOMEID"}
    {"result":null,"error":{"code":SOMEINT,"message":SOMESTRING},"id":"SOMEID"}

For requests, the params field can vary in what it contains depending on the
method (a.k.a. command) being sent.  Each parameter can be as simple as an int
or a complex structure containing many nested fields.  The id field is used to
identify a request and will be included in the associated response.

When working with asynchronous transports, such as websockets, spontaneous
notifications are also possible.  As indicated, they are the same as a request
object, except they have the id field set to null.  Therefore, servers will
ignore requests with the id field set to null, while clients can choose to
consume or ignore them.

Unfortunately, the original Bitcoin JSON-RPC API (and hence anything compatible
with it) doesn't always follow the spec and will sometimes return an error
string in the result field with a null error for certain commands.  However,
for the most part, the error field will be set as described on failure.

Marshalling and Unmarshalling

Based upon the discussion above, it should be easy to see how the types of this
package map into the required parts of the protocol

  - Request Objects (type Request)
    - Commands (type <Foo>Cmd)
    - Notifications (type <Foo>Ntfn)
  - Response Objects (type Response)
    - Result (type <Foo>Result)

To simplify the marshalling of the requests and responses, the MarshalCmd and
MarshalResponse functions are provided.  They return the raw bytes ready to be
sent across the wire.

Unmarshalling a received Request object is a two step process:
  1) Unmarshal the raw bytes into a Request struct instance via json.Unmarshal
  2) Use UnmarshalCmd on the Result field of the unmarshalled Request to create
     a concrete command or notification instance with all struct fields set
     accordingly

This approach is used since it provides the caller with access to the additional
fields in the request that are not part of the command such as the ID.

Unmarshalling a received Response object is also a two step process:
  1) Unmarhsal the raw bytes into a Response struct instance via json.Unmarshal
  2) Depending on the ID, unmarshal the Result field of the unmarshalled
     Response to create a concrete type instance

As above, this approach is used since it provides the caller with access to the
fields in the response such as the ID and Error.

Command Creation

This package provides two approaches for creating a new command.  This first,
and preferred, method is to use one of the New<Foo>Cmd functions.  This allows
static compile-time checking to help ensure the parameters stay in sync with
the struct definitions.

The second approach is the NewCmd function which takes a method (command) name
and variable arguments.  The function includes full checking to ensure the
parameters are accurate according to provided method, however these checks are,
obviously, run-time which means any mistakes won't be found until the code is
actually executed.  However, it is quite useful for user-supplied commands
that are intentionally dynamic.

Custom Command Registration

The command handling of this package is built around the concept of registered
commands.  This is true for the wide variety of commands already provided by the
package, but it also means caller can easily provide custom commands with all
of the same functionality as the built-in commands.  Use the RegisterCmd
function for this purpose.

A list of all registered methods can be obtained with the RegisteredCmdMethods
function.

Command Inspection

All registered commands are registered with flags that identify information such
as whether the command applies to a chain server, wallet server, or is a
notification along with the method name to use.  These flags can be obtained
with the MethodUsageFlags flags, and the method can be obtained with the
CmdMethod function.

Help Generation

To facilitate providing consistent help to users of the RPC server, this package
exposes the GenerateHelp and function which uses reflection on registered
commands or notifications, as well as the provided expected result types, to
generate the final help text.

In addition, the MethodUsageText function is provided to generate consistent
one-line usage for registered commands and notifications using reflection.

Errors

There are 2 distinct type of errors supported by this package:

  - General errors related to marshalling or unmarshalling or improper use of
    the package (type Error)
  - RPC errors which are intended to be returned across the wire as a part of
    the JSON-RPC response (type RPCError)

The first category of errors (type Error) typically indicates a programmer error
and can be avoided by properly using the API.  Errors of this type will be
returned from the various functions available in this package.  They identify
issues such as unsupported field types, attempts to register malformed commands,
and attempting to create a new command with an improper number of parameters.
The specific reason for the error can be detected by type asserting it to a
*btcjson.Error and accessing the ErrorCode field.

The second category of errors (type RPCError), on the other hand, are useful for
returning errors to RPC clients.  Consequently, they are used in the previously
described Response type.
*/
package btcjson
