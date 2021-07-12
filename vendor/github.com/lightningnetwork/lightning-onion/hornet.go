package sphinx

import (
	"github.com/btcsuite/btcd/btcec"
	"golang.org/x/crypto/ripemd160"
)

// TODO(roasbeef): Might need to change? due to the PRG* requirements?
const fSLength = 48

// Hmm appears that they use k = 128 throughout the paper?

// HMAC -> SHA-256
//  * or could use Poly1035: https://godoc.org/golang.org/x/crypto/poly1305
//  * but, the paper specs: {0, 1}^k x {0, 1}* -> {0, 1}^k
//  * Poly1035 is actually: {0, 1}^k x {0, 1}* -> {0, 1}^(2/k)
//  * Also with Poly, I guess the key is treated as a nonce, tagging two messages
//    with the same key allows an attacker to forge message or something like that

// Size of a forwarding segment is 32 bytes, the MAC is 16 bytes, so c = 48 bytes
//  * NOTE: this doesn't include adding R to the forwarding segment, and w/e esle

// Hmmm since each uses diff key, just use AES-CTR with blank nonce, given key,
// encrypt plaintext of all zeros, this'll give us our len(plaintext) rand bytes.
// PRG0 -> {0, 1}^k -> {0, 1}^r(c+k) or {0, 1}^1280  (assuming 20 hops, like rusty, but, is that too large? maybe, idk)
// PRG1 -> {0, 1}^k -> {0, 1}^r(c+k) or {0, 1}^1280  (assuming 20 hops)
// PRG2 -> {0, 1}^k -> {0, 1}^rc or {0, 1}^960 (assuming 20 hops, c=48)
//  * NOTE: in second version of paper (accepted to CCS'15), all the PRG*'s are like PRG2
//  * so makes it simpler

// PRP -> AES? or
//  * {0, 1}^k x {0, 1}^a -> {0, 1}^a

// Do we need AEAD for the below? Or are is the per-hop MAC okay?
// ENC: AES-CTR or CHACHA20?

// DEC: AES-CTR or CHACHA20?

// h_op: G^* -> {0, 1}^k
//  * op (elem of) {MAC, PRGO, PRG!, PRP, ENC, DEC}
//  * key gen for the above essentially

// RoutingSegment...
// NOTE: Length of routing segment in the paper is 8 bytes (enough for their
// imaginary network, I guess). But, looking like they'll be (20 + 33 bytes)
// 53 bytes. Or 52 if we use curve25519
type routingSegment struct {
	nextHop *btcec.PublicKey // NOTE: or, is this a LN addr? w/e that is?
	// nextHop [32]byte
	rCommitment [ripemd160.Size]byte

	// stuff perhaps?
}

// SphinxPayload...
type sphinxPayload struct {
}

// ForwardingSegment....
type forwardingSegment struct {
	// Here's hash(R), attempt to make an HTLC with the next hop. If
	// successful, then pass along the onion so we can finish getting the
	// payment circuit set up.
	// TODO(roasbeef): Do we create HTLC's with the minimum amount
	// possible? 1 satoshi or is it 1 mili-satoshi?
	rs routingSegment

	// To defend against replay attacks. Intermediate nodes will drop the
	// FS if it deems it's expired.
	expiration uint64

	// Key shared by intermediate node with the source, used to peel a layer
	// off the onion for the next hop.
	sharedSymmetricKey [32]byte // TODO(roasbeef): or, 16?
}

// AnonymousHeader...
type anonymousHeader struct {
	// Forwarding info for the current hop. When serialized, it'll be
	// encrypted with SV, the secret key for this node known to no-one but
	// the node. It also contains a secret key shared with this node and the
	// source, so it can peel off a layer of the onion for the next hop.
	fs forwardingSegment

	mac [32]byte // TODO(roasbeef): or, 16?
}

// CommonHeader...
type commonHeader struct {
	// TODO(roasbeef): maybe can use this to extend HORNET with additiona control signals
	// for LN nodes?
	controlType uint8
	hops        uint8
	nonce       [8]byte // either interpreted as EXP or nonce, little-endian? idk
}

// DataPacket...
type dataPacket struct {
	chdr  commonHeader
	ahdr  anonymousHeader             // TODO(roasbeef): MAC in ahdr includes the chdr?
	onion [fSLength * NumMaxHops]byte // TODO(roasbeef): or, is it NumMaxHops - 1?
}

type sphinxHeader struct {
}

// SessionSetupPacket...
type sessionSetupPacket struct {
	chdr      commonHeader
	shdr      sphinxHeader
	sp        sphinxPayload
	fsPayload [fSLength * NumMaxHops]byte // ? r*c
	// TODO(roabeef): hmm does this implcitly mean messages are a max of 48 bytes?
}
