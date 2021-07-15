package lncfg

// Tor holds the configuration options for the daemon's connection to tor.
type Tor struct {
	Active            bool   `long:"active" description:"Allow outbound and inbound connections to be routed through Tor"`
	SOCKS             string `long:"socks" description:"The host:port that Tor's exposed SOCKS5 proxy is listening on"`
	DNS               string `long:"dns" description:"The DNS server as host:port that Tor will use for SRV queries - NOTE must have TCP resolution enabled"`
	StreamIsolation   bool   `long:"streamisolation" description:"Enable Tor stream isolation by randomizing user credentials for each connection."`
	DirectConnections bool   `long:"directconnections" description:"Allow the node to establish direct connections to services not running behind Tor."`
	Control           string `long:"control" description:"The host:port that Tor is listening on for Tor control connections"`
	TargetIPAddress   string `long:"targetipaddress" description:"IP address that Tor should use as the target of the hidden service"`
	Password          string `long:"password" description:"The password used to arrive at the HashedControlPassword for the control port. If provided, the HASHEDPASSWORD authentication method will be used instead of the SAFECOOKIE one."`
	V2                bool   `long:"v2" description:"Automatically set up a v2 onion service to listen for inbound connections"`
	V3                bool   `long:"v3" description:"Automatically set up a v3 onion service to listen for inbound connections"`
	PrivateKeyPath    string `long:"privatekeypath" description:"The path to the private key of the onion service being created"`
	WatchtowerKeyPath string `long:"watchtowerkeypath" description:"The path to the private key of the watchtower onion service being created"`
}
