package sphinx

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
)

const (
	// addressSize is the length of the serialized address used to uniquely
	// identify the next hop to forward the onion to. BOLT 04 defines this
	// as 8 byte channel_id.
	AddressSize = 8

	// RealmByteSize is the number of bytes that the realm byte occupies.
	RealmByteSize = 1

	// AmtForwardSize is the number of bytes that the amount to forward
	// occupies.
	AmtForwardSize = 8

	// OutgoingCLTVSize is the number of bytes that the outgoing CLTV value
	// occupies.
	OutgoingCLTVSize = 4

	// NumPaddingBytes is the number of padding bytes in the hopData. These
	// bytes are currently unused within the protocol, and are reserved for
	// future use. However, if a hop contains extra data, then we'll
	// utilize this space to pack in the unrolled bytes.
	NumPaddingBytes = 12

	// LegacyHopDataSize is the fixed size of hop_data. BOLT 04 currently
	// specifies this to be 1 byte realm, 8 byte channel_id, 8 byte amount
	// to forward, 4 byte outgoing CLTV value, 12 bytes padding and 32 bytes
	// HMAC for a total of 65 bytes per hop.
	LegacyHopDataSize = (RealmByteSize + AddressSize + AmtForwardSize +
		OutgoingCLTVSize + NumPaddingBytes + HMACSize)

	// MaxPayloadSize is the maximum size a payload for a single hop can be.
	// This is the worst case scenario of a single hop, consuming all
	// available space. We need to know this in order to generate a
	// sufficiently long stream of pseudo-random bytes when
	// encrypting/decrypting the payload.
	MaxPayloadSize = routingInfoSize

	// routingInfoSize is the fixed size of the the routing info. This
	// consists of a addressSize byte address and a HMACSize byte HMAC for
	// each hop of the route, the first pair in cleartext and the following
	// pairs increasingly obfuscated. If not all space is used up, the
	// remainder is padded with null-bytes, also obfuscated.
	routingInfoSize = 1300

	// numStreamBytes is the number of bytes produced by our CSPRG for the
	// key stream implementing our stream cipher to encrypt/decrypt the mix
	// header. The MaxPayloadSize bytes at the end are used to
	// encrypt/decrypt the fillers when processing the packet of generating
	// the HMACs when creating the packet.
	numStreamBytes = routingInfoSize * 2

	// keyLen is the length of the keys used to generate cipher streams and
	// encrypt payloads. Since we use SHA256 to generate the keys, the
	// maximum length currently is 32 bytes.
	keyLen = 32

	// baseVersion represent the current supported version of onion packet.
	baseVersion = 0
)

var (
	ErrMaxRoutingInfoSizeExceeded = fmt.Errorf(
		"max routing info size of %v bytes exceeded", routingInfoSize)
)

// OnionPacket is the onion wrapped hop-to-hop routing information necessary to
// propagate a message through the mix-net without intermediate nodes having
// knowledge of their position within the route, the source, the destination,
// and finally the identities of the past/future nodes in the route. At each
// hop the ephemeral key is used by the node to perform ECDH between itself and
// the source node. This derived secret key is used to check the MAC of the
// entire mix header, decrypt the next set of routing information, and
// re-randomize the ephemeral key for the next node in the path. This per-hop
// re-randomization allows us to only propagate a single group element through
// the onion route.
type OnionPacket struct {
	// Version denotes the version of this onion packet. The version
	// indicates how a receiver of the packet should interpret the bytes
	// following this version byte. Currently, a version of 0x00 is the
	// only defined version type.
	Version byte

	// EphemeralKey is the public key that each hop will used in
	// combination with the private key in an ECDH to derive the shared
	// secret used to check the HMAC on the packet and also decrypted the
	// routing information.
	EphemeralKey *btcec.PublicKey

	// RoutingInfo is the full routing information for this onion packet.
	// This encodes all the forwarding instructions for this current hop
	// and all the hops in the route.
	RoutingInfo [routingInfoSize]byte

	// HeaderMAC is an HMAC computed with the shared secret of the routing
	// data and the associated data for this route. Including the
	// associated data lets each hop authenticate higher-level data that is
	// critical for the forwarding of this HTLC.
	HeaderMAC [HMACSize]byte
}

// generateSharedSecrets by the given nodes pubkeys, generates the shared
// secrets.
func generateSharedSecrets(paymentPath []*btcec.PublicKey,
	sessionKey *btcec.PrivateKey) ([]Hash256, error) {

	// Each hop performs ECDH with our ephemeral key pair to arrive at a
	// shared secret. Additionally, each hop randomizes the group element
	// for the next hop by multiplying it by the blinding factor. This way
	// we only need to transmit a single group element, and hops can't link
	// a session back to us if they have several nodes in the path.
	numHops := len(paymentPath)
	hopSharedSecrets := make([]Hash256, numHops)

	// Compute the triplet for the first hop outside of the main loop.
	// Within the loop each new triplet will be computed recursively based
	// off of the blinding factor of the last hop.
	lastEphemeralPubKey := sessionKey.PubKey()
	sessionKeyECDH := &PrivKeyECDH{PrivKey: sessionKey}
	sharedSecret, err := sessionKeyECDH.ECDH(paymentPath[0])
	if err != nil {
		return nil, err
	}
	hopSharedSecrets[0] = sharedSecret
	lastBlindingFactor := computeBlindingFactor(
		lastEphemeralPubKey, hopSharedSecrets[0][:],
	)

	// The cached blinding factor will contain the running product of the
	// session private key x and blinding factors b_i, computed as
	//   c_0 = x
	//   c_i = c_{i-1} * b_{i-1} 		 (mod |F(G)|).
	//       = x * b_0 * b_1 * ... * b_{i-1} (mod |F(G)|).
	//
	// We begin with just the session private key x, so that base case
	// c_0 = x. At the beginning of each iteration, the previous blinding
	// factor is aggregated into the modular product, and used as the scalar
	// value in deriving the hop ephemeral keys and shared secrets.
	var cachedBlindingFactor big.Int
	cachedBlindingFactor.SetBytes(sessionKey.D.Bytes())

	// Now recursively compute the cached blinding factor, ephemeral ECDH
	// pub keys, and shared secret for each hop.
	var nextBlindingFactor big.Int
	for i := 1; i <= numHops-1; i++ {
		// Update the cached blinding factor with b_{i-1}.
		nextBlindingFactor.SetBytes(lastBlindingFactor[:])
		cachedBlindingFactor.Mul(&cachedBlindingFactor, &nextBlindingFactor)
		cachedBlindingFactor.Mod(&cachedBlindingFactor, btcec.S256().Params().N)

		// a_i = g ^ c_i
		//     = g^( x * b_0 * ... * b_{i-1} )
		//     = X^( b_0 * ... * b_{i-1} )
		// X_our_session_pub_key x all prev blinding factors
		lastEphemeralPubKey = blindBaseElement(cachedBlindingFactor.Bytes())

		// e_i = Y_i ^ c_i
		//     = ( Y_i ^ x )^( b_0 * ... * b_{i-1} )
		// (Y_their_pub_key x x_our_priv) x all prev blinding factors
		hopBlindedPubKey := blindGroupElement(
			paymentPath[i], cachedBlindingFactor.Bytes(),
		)

		// s_i = sha256( e_i )
		//     = sha256( Y_i ^ (x * b_0 * ... * b_{i-1} )
		hopSharedSecrets[i] = sha256.Sum256(hopBlindedPubKey.SerializeCompressed())

		// Only need to evaluate up to the penultimate blinding factor.
		if i >= numHops-1 {
			break
		}

		// b_i = sha256( a_i || s_i )
		lastBlindingFactor = computeBlindingFactor(
			lastEphemeralPubKey, hopSharedSecrets[i][:],
		)
	}

	return hopSharedSecrets, nil
}

// NewOnionPacket creates a new onion packet which is capable of obliviously
// routing a message through the mix-net path outline by 'paymentPath'.
func NewOnionPacket(paymentPath *PaymentPath, sessionKey *btcec.PrivateKey,
	assocData []byte, pktFiller PacketFiller) (*OnionPacket, error) {

	// Check whether total payload size doesn't exceed the hard maximum.
	if paymentPath.TotalPayloadSize() > routingInfoSize {
		return nil, ErrMaxRoutingInfoSizeExceeded
	}

	// If we don't actually have a partially populated route, then we'll
	// exit early.
	numHops := paymentPath.TrueRouteLength()
	if numHops == 0 {
		return nil, fmt.Errorf("route of length zero passed in")
	}

	// We'll force the caller to provide a packet filler, as otherwise we
	// may default to an insecure filling method (which should only really
	// be used to generate test vectors).
	if pktFiller == nil {
		return nil, fmt.Errorf("packet filler must be specified")
	}

	hopSharedSecrets, err := generateSharedSecrets(
		paymentPath.NodeKeys(), sessionKey,
	)
	if err != nil {
		return nil, fmt.Errorf("error generating shared secret: %v", err)
	}

	// Generate the padding, called "filler strings" in the paper.
	filler := generateHeaderPadding("rho", paymentPath, hopSharedSecrets)

	// Allocate zero'd out byte slices to store the final mix header packet
	// and the hmac for each hop.
	var (
		mixHeader     [routingInfoSize]byte
		nextHmac      [HMACSize]byte
		hopPayloadBuf bytes.Buffer
	)

	// Fill the packet using the caller specified methodology.
	if err := pktFiller(sessionKey, &mixHeader); err != nil {
		return nil, err
	}

	// Now we compute the routing information for each hop, along with a
	// MAC of the routing info using the shared key for that hop.
	for i := numHops - 1; i >= 0; i-- {
		// We'll derive the two keys we need for each hop in order to:
		// generate our stream cipher bytes for the mixHeader, and
		// calculate the MAC over the entire constructed packet.
		rhoKey := generateKey("rho", &hopSharedSecrets[i])
		muKey := generateKey("mu", &hopSharedSecrets[i])

		// The HMAC for the final hop is simply zeroes. This allows the
		// last hop to recognize that it is the destination for a
		// particular payment.
		paymentPath[i].HopPayload.HMAC = nextHmac

		// Next, using the key dedicated for our stream cipher, we'll
		// generate enough bytes to obfuscate this layer of the onion
		// packet.
		streamBytes := generateCipherStream(rhoKey, routingInfoSize)
		payload := paymentPath[i].HopPayload

		// Before we assemble the packet, we'll shift the current
		// mix-header to the right in order to make room for this next
		// per-hop data.
		shiftSize := payload.NumBytes()
		rightShift(mixHeader[:], shiftSize)

		err := payload.Encode(&hopPayloadBuf)
		if err != nil {
			return nil, err
		}

		copy(mixHeader[:], hopPayloadBuf.Bytes())

		// Once the packet for this hop has been assembled, we'll
		// re-encrypt the packet by XOR'ing with a stream of bytes
		// generated using our shared secret.
		xor(mixHeader[:], mixHeader[:], streamBytes[:])

		// If this is the "last" hop, then we'll override the tail of
		// the hop data.
		if i == numHops-1 {
			copy(mixHeader[len(mixHeader)-len(filler):], filler)
		}

		// The packet for this hop consists of: mixHeader. When
		// calculating the MAC, we'll also include the optional
		// associated data which can allow higher level applications to
		// prevent replay attacks.
		packet := append(mixHeader[:], assocData...)
		nextHmac = calcMac(muKey, packet)

		hopPayloadBuf.Reset()
	}

	return &OnionPacket{
		Version:      baseVersion,
		EphemeralKey: sessionKey.PubKey(),
		RoutingInfo:  mixHeader,
		HeaderMAC:    nextHmac,
	}, nil
}

// rightShift shifts the byte-slice by the given number of bytes to the right
// and 0-fill the resulting gap.
func rightShift(slice []byte, num int) {
	for i := len(slice) - num - 1; i >= 0; i-- {
		slice[num+i] = slice[i]
	}

	for i := 0; i < num; i++ {
		slice[i] = 0
	}
}

// generateHeaderPadding derives the bytes for padding the mix header to ensure
// it remains fixed sized throughout route transit. At each step, we add
// 'frameSize*frames' padding of zeroes, concatenate it to the previous filler,
// then decrypt it (XOR) with the secret key of the current hop. When
// encrypting the mix header we essentially do the reverse of this operation:
// we "encrypt" the padding, and drop 'frameSize*frames' number of zeroes. As
// nodes process the mix header they add the padding ('frameSize*frames') in
// order to check the MAC and decrypt the next routing information eventually
// leaving only the original "filler" bytes produced by this function at the
// last hop.  Using this methodology, the size of the field stays constant at
// each hop.
func generateHeaderPadding(key string, path *PaymentPath, sharedSecrets []Hash256) []byte {
	numHops := path.TrueRouteLength()

	// We have to generate a filler that matches all but the last hop (the
	// last hop won't generate an HMAC)
	fillerSize := path.TotalPayloadSize() - path[numHops-1].HopPayload.NumBytes()
	filler := make([]byte, fillerSize)

	for i := 0; i < numHops-1; i++ {
		// Sum up how many frames were used by prior hops.
		fillerStart := routingInfoSize
		for _, p := range path[:i] {
			fillerStart -= p.HopPayload.NumBytes()
		}

		// The filler is the part dangling off of the end of the
		// routingInfo, so offset it from there, and use the current
		// hop's frame count as its size.
		fillerEnd := routingInfoSize + path[i].HopPayload.NumBytes()

		streamKey := generateKey(key, &sharedSecrets[i])
		streamBytes := generateCipherStream(streamKey, numStreamBytes)

		xor(filler, filler, streamBytes[fillerStart:fillerEnd])
	}

	return filler
}

// Encode serializes the raw bytes of the onion packet into the passed
// io.Writer. The form encoded within the passed io.Writer is suitable for
// either storing on disk, or sending over the network.
func (f *OnionPacket) Encode(w io.Writer) error {
	ephemeral := f.EphemeralKey.SerializeCompressed()

	if _, err := w.Write([]byte{f.Version}); err != nil {
		return err
	}

	if _, err := w.Write(ephemeral); err != nil {
		return err
	}

	if _, err := w.Write(f.RoutingInfo[:]); err != nil {
		return err
	}

	if _, err := w.Write(f.HeaderMAC[:]); err != nil {
		return err
	}

	return nil
}

// Decode fully populates the target ForwardingMessage from the raw bytes
// encoded within the io.Reader. In the case of any decoding errors, an error
// will be returned. If the method success, then the new OnionPacket is ready
// to be processed by an instance of SphinxNode.
func (f *OnionPacket) Decode(r io.Reader) error {
	var err error

	var buf [1]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return err
	}
	f.Version = buf[0]

	// If version of the onion packet protocol unknown for us than in might
	// lead to improperly decoded data.
	if f.Version != baseVersion {
		return ErrInvalidOnionVersion
	}

	var ephemeral [33]byte
	if _, err := io.ReadFull(r, ephemeral[:]); err != nil {
		return err
	}
	f.EphemeralKey, err = btcec.ParsePubKey(ephemeral[:], btcec.S256())
	if err != nil {
		return ErrInvalidOnionKey
	}

	if _, err := io.ReadFull(r, f.RoutingInfo[:]); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, f.HeaderMAC[:]); err != nil {
		return err
	}

	return nil
}

// ProcessCode is an enum-like type which describes to the high-level package
// user which action should be taken after processing a Sphinx packet.
type ProcessCode int

const (
	// ExitNode indicates that the node which processed the Sphinx packet
	// is the destination hop in the route.
	ExitNode = iota

	// MoreHops indicates that there are additional hops left within the
	// route. Therefore the caller should forward the packet to the node
	// denoted as the "NextHop".
	MoreHops

	// Failure indicates that a failure occurred during packet processing.
	Failure
)

// String returns a human readable string for each of the ProcessCodes.
func (p ProcessCode) String() string {
	switch p {
	case ExitNode:
		return "ExitNode"
	case MoreHops:
		return "MoreHops"
	case Failure:
		return "Failure"
	default:
		return "Unknown"
	}
}

// ProcessedPacket encapsulates the resulting state generated after processing
// an OnionPacket. A processed packet communicates to the caller what action
// should be taken after processing.
type ProcessedPacket struct {
	// Action represents the action the caller should take after processing
	// the packet.
	Action ProcessCode

	// ForwardingInstructions is the per-hop payload recovered from the
	// initial encrypted onion packet. It details how the packet should be
	// forwarded and also includes information that allows the processor of
	// the packet to authenticate the information passed within the HTLC.
	//
	// NOTE: This field will only be populated iff the above Action is
	// MoreHops.
	ForwardingInstructions *HopData

	// Payload is the raw payload as extracted from the packet. If the
	// ForwardingInstructions field above is nil, then this is a modern TLV
	// payload. As a result, the caller should parse the contents to obtain
	// the new set of forwarding instructions.
	Payload HopPayload

	// NextPacket is the onion packet that should be forwarded to the next
	// hop as denoted by the ForwardingInstructions field.
	//
	// NOTE: This field will only be populated iff the above Action is
	// MoreHops.
	NextPacket *OnionPacket
}

// Router is an onion router within the Sphinx network. The router is capable
// of processing incoming Sphinx onion packets thereby "peeling" a layer off
// the onion encryption which the packet is wrapped with.
type Router struct {
	nodeID   [AddressSize]byte
	nodeAddr *btcutil.AddressPubKeyHash

	onionKey SingleKeyECDH

	log ReplayLog
}

// NewRouter creates a new instance of a Sphinx onion Router given the node's
// currently advertised onion private key, and the target Bitcoin network.
func NewRouter(nodeKey SingleKeyECDH, net *chaincfg.Params, log ReplayLog) *Router {
	var nodeID [AddressSize]byte
	copy(nodeID[:], btcutil.Hash160(nodeKey.PubKey().SerializeCompressed()))

	// Safe to ignore the error here, nodeID is 20 bytes.
	nodeAddr, _ := btcutil.NewAddressPubKeyHash(nodeID[:], net)

	return &Router{
		nodeID:   nodeID,
		nodeAddr: nodeAddr,
		onionKey: nodeKey,
		log:      log,
	}
}

// Start starts / opens the ReplayLog's channeldb and its accompanying
// garbage collector goroutine.
func (r *Router) Start() error {
	return r.log.Start()
}

// Stop stops / closes the ReplayLog's channeldb and its accompanying
// garbage collector goroutine.
func (r *Router) Stop() {
	r.log.Stop()
}

// ProcessOnionPacket processes an incoming onion packet which has been forward
// to the target Sphinx router. If the encoded ephemeral key isn't on the
// target Elliptic Curve, then the packet is rejected. Similarly, if the
// derived shared secret has been seen before the packet is rejected.  Finally
// if the MAC doesn't check the packet is again rejected.
//
// In the case of a successful packet processing, and ProcessedPacket struct is
// returned which houses the newly parsed packet, along with instructions on
// what to do next.
func (r *Router) ProcessOnionPacket(onionPkt *OnionPacket,
	assocData []byte, incomingCltv uint32) (*ProcessedPacket, error) {

	// Compute the shared secret for this onion packet.
	sharedSecret, err := r.generateSharedSecret(onionPkt.EphemeralKey)
	if err != nil {
		return nil, err
	}

	// Additionally, compute the hash prefix of the shared secret, which
	// will serve as an identifier for detecting replayed packets.
	hashPrefix := hashSharedSecret(&sharedSecret)

	// Continue to optimistically process this packet, deferring replay
	// protection until the end to reduce the penalty of multiple IO
	// operations.
	packet, err := processOnionPacket(onionPkt, &sharedSecret, assocData, r)
	if err != nil {
		return nil, err
	}

	// Atomically compare this hash prefix with the contents of the on-disk
	// log, persisting it only if this entry was not detected as a replay.
	if err := r.log.Put(hashPrefix, incomingCltv); err != nil {
		return nil, err
	}

	return packet, nil
}

// ReconstructOnionPacket rederives the subsequent onion packet.
//
// NOTE: This method does not do any sort of replay protection, and should only
// be used to reconstruct packets that were successfully processed previously.
func (r *Router) ReconstructOnionPacket(onionPkt *OnionPacket,
	assocData []byte) (*ProcessedPacket, error) {

	// Compute the shared secret for this onion packet.
	sharedSecret, err := r.generateSharedSecret(onionPkt.EphemeralKey)
	if err != nil {
		return nil, err
	}

	return processOnionPacket(onionPkt, &sharedSecret, assocData, r)
}

// unwrapPacket wraps a layer of the passed onion packet using the specified
// shared secret and associated data. The associated data will be used to check
// the HMAC at each hop to ensure the same data is passed along with the onion
// packet. This function returns the next inner onion packet layer, along with
// the hop data extracted from the outer onion packet.
func unwrapPacket(onionPkt *OnionPacket, sharedSecret *Hash256,
	assocData []byte) (*OnionPacket, *HopPayload, error) {

	dhKey := onionPkt.EphemeralKey
	routeInfo := onionPkt.RoutingInfo
	headerMac := onionPkt.HeaderMAC

	// Using the derived shared secret, ensure the integrity of the routing
	// information by checking the attached MAC without leaking timing
	// information.
	message := append(routeInfo[:], assocData...)
	calculatedMac := calcMac(generateKey("mu", sharedSecret), message)
	if !hmac.Equal(headerMac[:], calculatedMac[:]) {
		return nil, nil, ErrInvalidOnionHMAC
	}

	// Attach the padding zeroes in order to properly strip an encryption
	// layer off the routing info revealing the routing information for the
	// next hop.
	streamBytes := generateCipherStream(
		generateKey("rho", sharedSecret), numStreamBytes,
	)
	zeroBytes := bytes.Repeat([]byte{0}, MaxPayloadSize)
	headerWithPadding := append(routeInfo[:], zeroBytes...)

	var hopInfo [numStreamBytes]byte
	xor(hopInfo[:], headerWithPadding, streamBytes)

	// Randomize the DH group element for the next hop using the
	// deterministic blinding factor.
	blindingFactor := computeBlindingFactor(dhKey, sharedSecret[:])
	nextDHKey := blindGroupElement(dhKey, blindingFactor[:])

	// With the MAC checked, and the payload decrypted, we can now parse
	// out the payload so we can derive the specified forwarding
	// instructions.
	var hopPayload HopPayload
	if err := hopPayload.Decode(bytes.NewReader(hopInfo[:])); err != nil {
		return nil, nil, err
	}

	// With the necessary items extracted, we'll copy of the onion packet
	// for the next node, snipping off our per-hop data.
	var nextMixHeader [routingInfoSize]byte
	copy(nextMixHeader[:], hopInfo[hopPayload.NumBytes():])
	innerPkt := &OnionPacket{
		Version:      onionPkt.Version,
		EphemeralKey: nextDHKey,
		RoutingInfo:  nextMixHeader,
		HeaderMAC:    hopPayload.HMAC,
	}

	return innerPkt, &hopPayload, nil
}

// processOnionPacket performs the primary key derivation and handling of onion
// packets. The processed packets returned from this method should only be used
// if the packet was not flagged as a replayed packet.
func processOnionPacket(onionPkt *OnionPacket, sharedSecret *Hash256,
	assocData []byte,
	sharedSecretGen sharedSecretGenerator) (*ProcessedPacket, error) {

	// First, we'll unwrap an initial layer of the onion packet. Typically,
	// we'll only have a single layer to unwrap, However, if the sender has
	// additional data for us within the Extra Onion Blobs (EOBs), then we
	// may have to unwrap additional layers.  By default, the inner most
	// mix header is the one that we'll want to pass onto the next hop so
	// they can properly check the HMAC and unwrap a layer for their
	// handoff hop.
	innerPkt, outerHopPayload, err := unwrapPacket(
		onionPkt, sharedSecret, assocData,
	)
	if err != nil {
		return nil, err
	}

	// By default we'll assume that there are additional hops in the route.
	// However if the uncovered 'nextMac' is all zeroes, then this
	// indicates that we're the final hop in the route.
	var action ProcessCode = MoreHops
	if bytes.Compare(zeroHMAC[:], outerHopPayload.HMAC[:]) == 0 {
		action = ExitNode
	}

	hopData, err := outerHopPayload.HopData()
	if err != nil {
		return nil, err
	}

	// Finally, we'll return a fully processed packet with the outer most
	// hop data (where the primary forwarding instructions lie) and the
	// inner most onion packet that we unwrapped.
	return &ProcessedPacket{
		Action:                 action,
		ForwardingInstructions: hopData,
		Payload:                *outerHopPayload,
		NextPacket:             innerPkt,
	}, nil
}

// Tx is a transaction consisting of a number of sphinx packets to be atomically
// written to the replay log. This structure helps to coordinate construction of
// the underlying Batch object, and to ensure that the result of the processing
// is idempotent.
type Tx struct {
	// batch is the set of packets to be incrementally processed and
	// ultimately committed in this transaction
	batch *Batch

	// router is a reference to the sphinx router that created this
	// transaction. Committing this transaction will utilize this router's
	// replay log.
	router *Router

	// packets contains a potentially sparse list of optimistically processed
	// packets for this batch. The contents of a particular index should
	// only be accessed if the index is *not* included in the replay set, or
	// otherwise failed any other stage of the processing.
	packets []ProcessedPacket
}

// BeginTxn creates a new transaction that can later be committed back to the
// sphinx router's replay log.
//
// NOTE: The nels parameter should represent the maximum number of that could
// be added to the batch, using sequence numbers that match or exceed this
// value could result in an out-of-bounds panic.
func (r *Router) BeginTxn(id []byte, nels int) *Tx {
	return &Tx{
		batch:   NewBatch(id),
		router:  r,
		packets: make([]ProcessedPacket, nels),
	}
}

// ProcessOnionPacket processes an incoming onion packet which has been forward
// to the target Sphinx router. If the encoded ephemeral key isn't on the
// target Elliptic Curve, then the packet is rejected. Similarly, if the
// derived shared secret has been seen before the packet is rejected.  Finally
// if the MAC doesn't check the packet is again rejected.
//
// In the case of a successful packet processing, and ProcessedPacket struct is
// returned which houses the newly parsed packet, along with instructions on
// what to do next.
func (t *Tx) ProcessOnionPacket(seqNum uint16, onionPkt *OnionPacket,
	assocData []byte, incomingCltv uint32) error {

	// Compute the shared secret for this onion packet.
	sharedSecret, err := t.router.generateSharedSecret(
		onionPkt.EphemeralKey,
	)
	if err != nil {
		return err
	}

	// Additionally, compute the hash prefix of the shared secret, which
	// will serve as an identifier for detecting replayed packets.
	hashPrefix := hashSharedSecret(&sharedSecret)

	// Continue to optimistically process this packet, deferring replay
	// protection until the end to reduce the penalty of multiple IO
	// operations.
	packet, err := processOnionPacket(
		onionPkt, &sharedSecret, assocData, t.router,
	)
	if err != nil {
		return err
	}

	// Add the hash prefix to pending batch of shared secrets that will be
	// written later via Commit().
	err = t.batch.Put(seqNum, hashPrefix, incomingCltv)
	if err != nil {
		return err
	}

	// If we successfully added this packet to the batch, cache the
	// processed packet within the Tx which can be accessed after
	// committing if this sequence number does not appear in the replay
	// set.
	t.packets[seqNum] = *packet

	return nil
}

// Commit writes this transaction's batch of sphinx packets to the replay log,
// performing a final check against the log for replays.
func (t *Tx) Commit() ([]ProcessedPacket, *ReplaySet, error) {
	if t.batch.IsCommitted {
		return t.packets, t.batch.ReplaySet, nil
	}

	rs, err := t.router.log.PutBatch(t.batch)

	return t.packets, rs, err
}
