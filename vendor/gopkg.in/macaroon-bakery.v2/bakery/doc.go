// The bakery package layers on top of the macaroon package, providing
// a transport and store-agnostic way of using macaroons to assert
// client capabilities.
//
// Summary
//
// The Bakery type is probably where you want to start.
// It encapsulates a Checker type, which performs checking
// of operations, and an Oven type, which encapsulates
// the actual details of the macaroon encoding conventions.
//
// Most other types and functions are designed either to plug
// into one of the above types (the various Authorizer
// implementations, for example), or to expose some independent
// functionality that's potentially useful (Discharge, for example).
//
// The rest of this introduction introduces some of the concepts
// used by the bakery package.
//
// Identity and entities
//
// An Identity represents some authenticated user (or agent), usually
// the client in a network protocol. An identity can be authenticated by
// an external identity server (with a third party macaroon caveat) or
// by locally provided information such as a username and password.
//
// The Checker type is not responsible for determining identity - that
// functionality is represented by the IdentityClient interface.
//
// The Checker uses identities to decide whether something should be
// allowed or not - the Authorizer interface is used to ask whether a
// given identity should be allowed to perform some set of operations.
//
// Operations
//
// An operation defines some requested action on an entity. For example,
// if file system server defines an entity for every file in the server,
// an operation to read a file might look like:
//
//     Op{
//		Entity: "/foo",
//		Action: "write",
//	}
//
// The exact set of entities and actions is up to the caller, but should
// be kept stable over time because authorization tokens will contain
// these names.
//
// To authorize some request on behalf of a remote user, first find out
// what operations that request needs to perform. For example, if the
// user tries to delete a file, the entity might be the path to the
// file's directory and the action might be "write". It may often be
// possible to determine the operations required by a request without
// reference to anything external, when the request itself contains all
// the necessary information.
//
// The LoginOp operation is special - any macaroon associated with this
// operation is treated as a bearer of identity information. If two
// valid LoginOp macaroons are presented, only the first one will be
// used for identity.
//
// Authorization
//
// The Authorizer interface is responsible for determining whether a
// given authenticated identity is authorized to perform a set of
// operations. This is used when the macaroons provided to Auth are not
// sufficient to authorize the operations themselves.
//
// Capabilities
//
// A "capability" is represented by a macaroon that's associated with
// one or more operations, and grants the capability to perform all
// those operations. The AllowCapability method reports whether a
// capability is allowed. It takes into account any authenticated
// identity and any other capabilities provided.
//
// Third party caveats
//
// Sometimes authorization will only be granted if a third party caveat
// is discharged. This will happen when an IdentityClient or Authorizer
// returns a third party caveat.
//
// When this happens, a DischargeRequiredError will be returned
// containing the caveats and the operations required. The caller is
// responsible for creating a macaroon with those caveats associated
// with those operations and for passing that macaroon to the client to
// discharge.
package bakery
