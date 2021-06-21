// +build !walletrpc

package walletrpc

const (
	// SubServerName is the name of the sub rpc server. We'll use this name
	// to register ourselves, and we also require that the main
	// SubServerConfigDispatcher instance recognize as the name of our
	SubServerName = "WalletKitRPC"
)

// Config is the primary configuration struct for the WalletKit RPC server.
// When the server isn't active (via the build flag), callers outside this
// package will see this shell of a config file.
type Config struct{}
