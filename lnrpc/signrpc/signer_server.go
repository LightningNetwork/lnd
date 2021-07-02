// +build signrpc

package signrpc

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

const (
	// subServerName is the name of the sub rpc server. We'll use this name
	// to register ourselves, and we also require that the main
	// SubServerConfigDispatcher instance recognize this as the name of the
	// config file that we need.
	subServerName = "SignRPC"
)

var (
	// macaroonOps are the set of capabilities that our minted macaroon (if
	// it doesn't already exist) will have.
	macaroonOps = []bakery.Op{
		{
			Entity: "signer",
			Action: "generate",
		},
		{
			Entity: "signer",
			Action: "read",
		},
	}

	// macPermissions maps RPC calls to the permissions they require.
	macPermissions = map[string][]bakery.Op{
		"/signrpc.Signer/SignOutputRaw": {{
			Entity: "signer",
			Action: "generate",
		}},
		"/signrpc.Signer/ComputeInputScript": {{
			Entity: "signer",
			Action: "generate",
		}},
		"/signrpc.Signer/SignMessage": {{
			Entity: "signer",
			Action: "generate",
		}},
		"/signrpc.Signer/VerifyMessage": {{
			Entity: "signer",
			Action: "read",
		}},
		"/signrpc.Signer/DeriveSharedKey": {{
			Entity: "signer",
			Action: "generate",
		}},
	}

	// DefaultSignerMacFilename is the default name of the signer macaroon
	// that we expect to find via a file handle within the main
	// configuration file in this package.
	DefaultSignerMacFilename = "signer.macaroon"
)

// ServerShell is a shell struct holding a reference to the actual sub-server.
// It is used to register the gRPC sub-server with the root server before we
// have the necessary dependencies to populate the actual sub-server.
type ServerShell struct {
	SignerServer
}

// Server is a sub-server of the main RPC server: the signer RPC. This sub RPC
// server allows external callers to access the full signing capabilities of
// lnd. This allows callers to create custom protocols, external to lnd, even
// backed by multiple distinct lnd across independent failure domains.
type Server struct {
	// Required by the grpc-gateway/v2 library for forward compatibility.
	UnimplementedSignerServer

	cfg *Config
}

// A compile time check to ensure that Server fully implements the SignerServer
// gRPC service.
var _ SignerServer = (*Server)(nil)

// New returns a new instance of the signrpc Signer sub-server. We also return
// the set of permissions for the macaroons that we may create within this
// method. If the macaroons we need aren't found in the filepath, then we'll
// create them on start up. If we're unable to locate, or create the macaroons
// we need, then we'll return with an error.
func New(cfg *Config) (*Server, lnrpc.MacaroonPerms, error) {
	// If the path of the signer macaroon wasn't generated, then we'll
	// assume that it's found at the default network directory.
	if cfg.SignerMacPath == "" {
		cfg.SignerMacPath = filepath.Join(
			cfg.NetworkDir, DefaultSignerMacFilename,
		)
	}

	// Now that we know the full path of the signer macaroon, we can check
	// to see if we need to create it or not. If stateless_init is set
	// then we don't write the macaroons.
	macFilePath := cfg.SignerMacPath
	if cfg.MacService != nil && !cfg.MacService.StatelessInit &&
		!lnrpc.FileExists(macFilePath) {

		log.Infof("Making macaroons for Signer RPC Server at: %v",
			macFilePath)

		// At this point, we know that the signer macaroon doesn't yet,
		// exist, so we need to create it with the help of the main
		// macaroon service.
		signerMac, err := cfg.MacService.NewMacaroon(
			context.Background(), macaroons.DefaultRootKeyID,
			macaroonOps...,
		)
		if err != nil {
			return nil, nil, err
		}
		signerMacBytes, err := signerMac.M().MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		err = ioutil.WriteFile(macFilePath, signerMacBytes, 0644)
		if err != nil {
			_ = os.Remove(macFilePath)
			return nil, nil, err
		}
	}

	signerServer := &Server{
		cfg: cfg,
	}

	return signerServer, macPermissions, nil
}

// Start launches any helper goroutines required for the rpcServer to function.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (s *Server) Start() error {
	return nil
}

// Stop signals any active goroutines for a graceful closure.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (s *Server) Stop() error {
	return nil
}

// Name returns a unique string representation of the sub-server. This can be
// used to identify the sub-server and also de-duplicate them.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (s *Server) Name() string {
	return subServerName
}

// RegisterWithRootServer will be called by the root gRPC server to direct a
// sub RPC server to register itself with the main gRPC root server. Until this
// is called, each sub-server won't be able to have
// requests routed towards it.
//
// NOTE: This is part of the lnrpc.GrpcHandler interface.
func (r *ServerShell) RegisterWithRootServer(grpcServer *grpc.Server) error {
	// We make sure that we register it with the main gRPC server to ensure
	// all our methods are routed properly.
	RegisterSignerServer(grpcServer, r)

	log.Debugf("Signer RPC server successfully register with root gRPC " +
		"server")

	return nil
}

// RegisterWithRestServer will be called by the root REST mux to direct a sub
// RPC server to register itself with the main REST mux server. Until this is
// called, each sub-server won't be able to have requests routed towards it.
//
// NOTE: This is part of the lnrpc.GrpcHandler interface.
func (r *ServerShell) RegisterWithRestServer(ctx context.Context,
	mux *runtime.ServeMux, dest string, opts []grpc.DialOption) error {

	// We make sure that we register it with the main REST server to ensure
	// all our methods are routed properly.
	err := RegisterSignerHandlerFromEndpoint(ctx, mux, dest, opts)
	if err != nil {
		log.Errorf("Could not register Signer REST server "+
			"with root REST server: %v", err)
		return err
	}

	log.Debugf("Signer REST server successfully registered with " +
		"root REST server")
	return nil
}

// CreateSubServer populates the subserver's dependencies using the passed
// SubServerConfigDispatcher. This method should fully initialize the
// sub-server instance, making it ready for action. It returns the macaroon
// permissions that the sub-server wishes to pass on to the root server for all
// methods routed towards it.
//
// NOTE: This is part of the lnrpc.GrpcHandler interface.
func (r *ServerShell) CreateSubServer(configRegistry lnrpc.SubServerConfigDispatcher) (
	lnrpc.SubServer, lnrpc.MacaroonPerms, error) {

	subServer, macPermissions, err := createNewSubServer(configRegistry)
	if err != nil {
		return nil, nil, err
	}

	r.SignerServer = subServer
	return subServer, macPermissions, nil
}

// SignOutputRaw generates a signature for the passed transaction according to
// the data within the passed SignReq. If we're unable to find the keys that
// correspond to the KeyLocators in the SignReq then we'll return an error.
// Additionally, if the user doesn't provide the set of required parameters, or
// provides an invalid transaction, then we'll return with an error.
//
// NOTE: The resulting signature should be void of a sighash byte.
func (s *Server) SignOutputRaw(ctx context.Context, in *SignReq) (*SignResp, error) {

	switch {
	// If the client doesn't specify a transaction, then there's nothing to
	// sign, so we'll exit early.
	case len(in.RawTxBytes) == 0:
		return nil, fmt.Errorf("a transaction to sign MUST be " +
			"passed in")

	// If the client doesn't tell us *how* to sign the transaction, then we
	// can't sign anything, so we'll exit early.
	case len(in.SignDescs) == 0:
		return nil, fmt.Errorf("at least one SignDescs MUST be " +
			"passed in")
	}

	// Now that we know we have an actual transaction to decode, we'll
	// deserialize it into something that we can properly utilize.
	var (
		txToSign wire.MsgTx
		err      error
	)
	txReader := bytes.NewReader(in.RawTxBytes)
	if err := txToSign.Deserialize(txReader); err != nil {
		return nil, fmt.Errorf("unable to decode tx: %v", err)
	}

	sigHashCache := txscript.NewTxSigHashes(&txToSign)

	log.Debugf("Generating sigs for %v inputs: ", len(in.SignDescs))

	// With the transaction deserialized, we'll now convert sign descs so
	// we can feed it into the actual signer.
	signDescs := make([]*input.SignDescriptor, 0, len(in.SignDescs))
	for _, signDesc := range in.SignDescs {
		keyDesc := signDesc.KeyDesc

		// The caller can either specify the key using the raw pubkey,
		// or the description of the key. We'll still attempt to parse
		// both if both were provided however, to ensure the underlying
		// SignOutputRaw has as much information as possible.
		var (
			targetPubKey *btcec.PublicKey
			keyLoc       keychain.KeyLocator
		)

		// If this method doesn't return nil, then we know that user is
		// attempting to include a raw serialized pub key.
		if keyDesc.GetRawKeyBytes() != nil {
			targetPubKey, err = parseRawKeyBytes(
				keyDesc.GetRawKeyBytes(),
			)
			if err != nil {
				return nil, err
			}
		}

		// Similarly, if they specified a key locator, then we'll parse
		// that as well.
		if keyDesc.GetKeyLoc() != nil {
			protoLoc := keyDesc.GetKeyLoc()
			keyLoc = keychain.KeyLocator{
				Family: keychain.KeyFamily(
					protoLoc.KeyFamily,
				),
				Index: uint32(protoLoc.KeyIndex),
			}
		}

		// If a witness script isn't passed, then we can't proceed, as
		// in the p2wsh case, we can't properly generate the sighash.
		if len(signDesc.WitnessScript) == 0 {
			// TODO(roasbeef): if regualr p2wkh, then at times
			// internally we allow script to go by
			return nil, fmt.Errorf("witness script MUST be " +
				"specified")
		}

		// If the users provided a double tweak, then we'll need to
		// parse that out now to ensure their input is properly signed.
		var tweakPrivKey *btcec.PrivateKey
		if len(signDesc.DoubleTweak) != 0 {
			tweakPrivKey, _ = btcec.PrivKeyFromBytes(
				btcec.S256(), signDesc.DoubleTweak,
			)
		}

		// Finally, with verification and parsing complete, we can
		// construct the final sign descriptor to generate the proper
		// signature for this input.
		signDescs = append(signDescs, &input.SignDescriptor{
			KeyDesc: keychain.KeyDescriptor{
				KeyLocator: keyLoc,
				PubKey:     targetPubKey,
			},
			SingleTweak:   signDesc.SingleTweak,
			DoubleTweak:   tweakPrivKey,
			WitnessScript: signDesc.WitnessScript,
			Output: &wire.TxOut{
				Value:    signDesc.Output.Value,
				PkScript: signDesc.Output.PkScript,
			},
			HashType:   txscript.SigHashType(signDesc.Sighash),
			SigHashes:  sigHashCache,
			InputIndex: int(signDesc.InputIndex),
		})
	}

	// Now that we've mapped all the proper sign descriptors, we can
	// request signatures for each of them, passing in the transaction to
	// be signed.
	numSigs := len(in.SignDescs)
	resp := &SignResp{
		RawSigs: make([][]byte, numSigs),
	}
	for i, signDesc := range signDescs {
		sig, err := s.cfg.Signer.SignOutputRaw(&txToSign, signDesc)
		if err != nil {
			log.Errorf("unable to generate sig for input "+
				"#%v: %v", i, err)

			return nil, err
		}

		resp.RawSigs[i] = sig.Serialize()
	}

	return resp, nil
}

// ComputeInputScript generates a complete InputIndex for the passed
// transaction with the signature as defined within the passed SignDescriptor.
// This method should be capable of generating the proper input script for both
// regular p2wkh output and p2wkh outputs nested within a regular p2sh output.
//
// Note that when using this method to sign inputs belonging to the wallet, the
// only items of the SignDescriptor that need to be populated are pkScript in
// the TxOut field, the value in that same field, and finally the input index.
func (s *Server) ComputeInputScript(ctx context.Context,
	in *SignReq) (*InputScriptResp, error) {

	switch {
	// If the client doesn't specify a transaction, then there's nothing to
	// sign, so we'll exit early.
	case len(in.RawTxBytes) == 0:
		return nil, fmt.Errorf("a transaction to sign MUST be " +
			"passed in")

	// If the client doesn't tell us *how* to sign the transaction, then we
	// can't sign anything, so we'll exit early.
	case len(in.SignDescs) == 0:
		return nil, fmt.Errorf("at least one SignDescs MUST be " +
			"passed in")
	}

	// Now that we know we have an actual transaction to decode, we'll
	// deserialize it into something that we can properly utilize.
	var txToSign wire.MsgTx
	txReader := bytes.NewReader(in.RawTxBytes)
	if err := txToSign.Deserialize(txReader); err != nil {
		return nil, fmt.Errorf("unable to decode tx: %v", err)
	}

	sigHashCache := txscript.NewTxSigHashes(&txToSign)

	signDescs := make([]*input.SignDescriptor, 0, len(in.SignDescs))
	for _, signDesc := range in.SignDescs {
		// For this method, the only fields that we care about are the
		// hash type, and the information concerning the output as we
		// only know how to provide full witnesses for outputs that we
		// solely control.
		signDescs = append(signDescs, &input.SignDescriptor{
			Output: &wire.TxOut{
				Value:    signDesc.Output.Value,
				PkScript: signDesc.Output.PkScript,
			},
			HashType:   txscript.SigHashType(signDesc.Sighash),
			SigHashes:  sigHashCache,
			InputIndex: int(signDesc.InputIndex),
		})
	}

	// With all of our signDescs assembled, we can now generate a valid
	// input script for each of them, and collate the responses to return
	// back to the caller.
	numWitnesses := len(in.SignDescs)
	resp := &InputScriptResp{
		InputScripts: make([]*InputScript, numWitnesses),
	}
	for i, signDesc := range signDescs {
		inputScript, err := s.cfg.Signer.ComputeInputScript(
			&txToSign, signDesc,
		)
		if err != nil {
			return nil, err
		}

		resp.InputScripts[i] = &InputScript{
			Witness:   inputScript.Witness,
			SigScript: inputScript.SigScript,
		}
	}

	return resp, nil
}

// SignMessage signs a message with the key specified in the key locator. The
// returned signature is fixed-size LN wire format encoded.
func (s *Server) SignMessage(ctx context.Context,
	in *SignMessageReq) (*SignMessageResp, error) {

	if in.Msg == nil {
		return nil, fmt.Errorf("a message to sign MUST be passed in")
	}
	if in.KeyLoc == nil {
		return nil, fmt.Errorf("a key locator MUST be passed in")
	}

	// Describe the private key we'll be using for signing.
	keyDescriptor := keychain.KeyDescriptor{
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(in.KeyLoc.KeyFamily),
			Index:  uint32(in.KeyLoc.KeyIndex),
		},
	}

	// The signature is over the sha256 hash of the message.
	var digest [32]byte
	copy(digest[:], chainhash.HashB(in.Msg))

	// Create the raw ECDSA signature first and convert it to the final wire
	// format after.
	sig, err := s.cfg.KeyRing.SignDigest(keyDescriptor, digest)
	if err != nil {
		return nil, fmt.Errorf("can't sign the hash: %v", err)
	}
	wireSig, err := lnwire.NewSigFromSignature(sig)
	if err != nil {
		return nil, fmt.Errorf("can't convert to wire format: %v", err)
	}
	return &SignMessageResp{
		Signature: wireSig.ToSignatureBytes(),
	}, nil
}

// VerifyMessage verifies a signature over a message using the public key
// provided. The signature must be fixed-size LN wire format encoded.
func (s *Server) VerifyMessage(ctx context.Context,
	in *VerifyMessageReq) (*VerifyMessageResp, error) {

	if in.Msg == nil {
		return nil, fmt.Errorf("a message to verify MUST be passed in")
	}
	if in.Signature == nil {
		return nil, fmt.Errorf("a signature to verify MUST be passed " +
			"in")
	}
	if in.Pubkey == nil {
		return nil, fmt.Errorf("a pubkey to verify MUST be passed in")
	}
	pubkey, err := btcec.ParsePubKey(in.Pubkey, btcec.S256())
	if err != nil {
		return nil, fmt.Errorf("unable to parse pubkey: %v", err)
	}

	// The signature must be fixed-size LN wire format encoded.
	wireSig, err := lnwire.NewSigFromRawSignature(in.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %v", err)
	}
	sig, err := wireSig.ToSignature()
	if err != nil {
		return nil, fmt.Errorf("failed to convert from wire format: %v",
			err)
	}

	// The signature is over the sha256 hash of the message.
	digest := chainhash.HashB(in.Msg)
	valid := sig.Verify(digest, pubkey)
	return &VerifyMessageResp{
		Valid: valid,
	}, nil
}

// DeriveSharedKey returns a shared secret key by performing Diffie-Hellman key
// derivation between the ephemeral public key in the request and the node's
// key specified in the key_desc parameter. Either a key locator or a raw public
// key is expected in the key_desc, if neither is supplied, defaults to the
// node's identity private key. The old key_loc parameter in the request
// shouldn't be used anymore.
// The resulting shared public key is serialized in the compressed format and
// hashed with sha256, resulting in the final key length of 256bit.
func (s *Server) DeriveSharedKey(_ context.Context, in *SharedKeyRequest) (
	*SharedKeyResponse, error) {

	// Check that EphemeralPubkey is valid.
	ephemeralPubkey, err := parseRawKeyBytes(in.EphemeralPubkey)
	if err != nil {
		return nil, fmt.Errorf("error in ephemeral pubkey: %v", err)
	}
	if ephemeralPubkey == nil {
		return nil, fmt.Errorf("must provide ephemeral pubkey")
	}

	// Check for backward compatibility. The caller either specifies the old
	// key_loc field, or the new key_desc field, but not both.
	if in.KeyDesc != nil && in.KeyLoc != nil {
		return nil, fmt.Errorf("use either key_desc or key_loc")
	}

	// When key_desc is used, the key_desc.key_loc is expected as the caller
	// needs to specify the KeyFamily.
	if in.KeyDesc != nil && in.KeyDesc.KeyLoc == nil {
		return nil, fmt.Errorf("when setting key_desc the field " +
			"key_desc.key_loc must also be set")
	}

	// We extract two params, rawKeyBytes and keyLoc. Notice their initial
	// values will be overwritten if not using the deprecated RPC param.
	var rawKeyBytes []byte
	keyLoc := in.KeyLoc
	if in.KeyDesc != nil {
		keyLoc = in.KeyDesc.GetKeyLoc()
		rawKeyBytes = in.KeyDesc.GetRawKeyBytes()
	}

	// When no keyLoc is supplied, defaults to the node's identity private
	// key.
	if keyLoc == nil {
		keyLoc = &KeyLocator{
			KeyFamily: int32(keychain.KeyFamilyNodeKey),
			KeyIndex:  0,
		}
	}

	// Check the caller is using either the key index or the raw public key
	// to perform the ECDH, we can't have both.
	if rawKeyBytes != nil && keyLoc.KeyIndex != 0 {
		return nil, fmt.Errorf("use either raw_key_bytes or key_index")
	}

	// Check the raw public key is valid. Notice that if the rawKeyBytes is
	// empty, the parseRawKeyBytes won't return an error, a nil
	// *btcec.PublicKey is returned instead.
	pk, err := parseRawKeyBytes(rawKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("error in raw pubkey: %v", err)
	}

	// Create a key descriptor. When the KeyIndex is not specified, it uses
	// the empty value 0, and when the raw public key is not specified, the
	// pk is nil.
	keyDescriptor := keychain.KeyDescriptor{
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(keyLoc.KeyFamily),
			Index:  uint32(keyLoc.KeyIndex),
		},
		PubKey: pk,
	}

	// Derive the shared key using ECDH and hashing the serialized
	// compressed shared point.
	sharedKeyHash, err := s.cfg.KeyRing.ECDH(keyDescriptor, ephemeralPubkey)
	if err != nil {
		err := fmt.Errorf("unable to derive shared key: %v", err)
		log.Error(err)
		return nil, err
	}

	return &SharedKeyResponse{SharedKey: sharedKeyHash[:]}, nil
}

// parseRawKeyBytes checks that the provided raw public key is valid and returns
// the public key. A nil public key is returned if the length of the rawKeyBytes
// is zero.
func parseRawKeyBytes(rawKeyBytes []byte) (*btcec.PublicKey, error) {
	switch {

	case len(rawKeyBytes) == 33:
		// If a proper raw key was provided, then we'll attempt
		// to decode and parse it.
		return btcec.ParsePubKey(
			rawKeyBytes, btcec.S256(),
		)

	case len(rawKeyBytes) == 0:
		// No key is provided, return nil.
		return nil, nil

	default:
		// If the user provided a raw key, but it's of the
		// wrong length, then we'll return with an error.
		return nil, fmt.Errorf("pubkey must be " +
			"serialized in compressed format if " +
			"specified")
	}
}
