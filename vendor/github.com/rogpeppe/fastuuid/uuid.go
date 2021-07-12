// Package fastuuid provides fast UUID generation of 192 bit
// universally unique identifiers.
//
// It also provides simple support for 128-bit RFC-4122 V4 UUID strings.
//
// Note that the generated UUIDs are not unguessable - each
// UUID generated from a Generator is adjacent to the
// previously generated UUID.
//
// By way of comparison with two other popular UUID-generation packages, github.com/satori/go.uuid
// and github.com/google/uuid, here are some benchmarks:
//
//	BenchmarkNext-4              	128272185	         9.20 ns/op
//	BenchmarkHex128-4            	14323180	        76.4 ns/op
//	BenchmarkContended-4         	45741997	        26.4 ns/op
//	BenchmarkSatoriNext-4        	 1231281	       967 ns/op
//	BenchmarkSatoriHex128-4      	 1000000	      1041 ns/op
//	BenchmarkSatoriContended-4   	 1765520	       666 ns/op
//	BenchmarkGoogleNext-4        	 1256250	       958 ns/op
//	BenchmarkGoogleHex128-4      	 1000000	      1044 ns/op
//	BenchmarkGoogleContended-4   	 1746570	       690 ns/op
package fastuuid

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync/atomic"
)

// Generator represents a UUID generator that
// generates UUIDs in sequence from a random starting
// point.
type Generator struct {
	// The constant seed. The first 8 bytes of this are
	// copied into counter and then ignored thereafter.
	seed    [24]byte
	counter uint64
}

// NewGenerator returns a new Generator.
// It can fail if the crypto/rand read fails.
func NewGenerator() (*Generator, error) {
	var g Generator
	_, err := rand.Read(g.seed[:])
	if err != nil {
		return nil, errors.New("cannot generate random seed: " + err.Error())
	}
	g.counter = binary.LittleEndian.Uint64(g.seed[:8])
	return &g, nil
}

// MustNewGenerator is like NewGenerator
// but panics on failure.
func MustNewGenerator() *Generator {
	g, err := NewGenerator()
	if err != nil {
		panic(err)
	}
	return g
}

// Next returns the next UUID from the generator.
// Only the first 8 bytes can differ from the previous
// UUID, so taking a slice of the first 16 bytes
// is sufficient to provide a somewhat less secure 128 bit UUID.
//
// It is OK to call this method concurrently.
func (g *Generator) Next() [24]byte {
	x := atomic.AddUint64(&g.counter, 1)
	uuid := g.seed
	binary.LittleEndian.PutUint64(uuid[:8], x)
	return uuid
}

// Hex128 is a convenience method that returns Hex128(g.Next()).
func (g *Generator) Hex128() string {
	return Hex128(g.Next())
}

// Hex128 returns an RFC4122 V4 representation of the
// first 128 bits of the given UUID. For example:
//
//	f81d4fae-7dec-41d0-8765-00a0c91e6bf6.
//
// Note: before encoding, it swaps bytes 6 and 9
// so that all the varying bits of the UUID as
// returned from Generator.Next are reflected
// in the Hex128 representation.
//
// If you want unpredictable UUIDs, you might want to consider
// hashing the uuid (using SHA256, for example) before passing it
// to Hex128.
func Hex128(uuid [24]byte) string {
	// As fastuuid only varies the first 8 bytes of the UUID and we
	// don't want to lose any of that variance, swap the UUID
	// version byte in that range for one outside it.
	uuid[6], uuid[9] = uuid[9], uuid[6]

	// Version 4.
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	// RFC4122 variant.
	uuid[8] = uuid[8]&0x3f | 0x80

	b := make([]byte, 36)
	hex.Encode(b[0:8], uuid[0:4])
	b[8] = '-'
	hex.Encode(b[9:13], uuid[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], uuid[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], uuid[8:10])
	b[23] = '-'
	hex.Encode(b[24:], uuid[10:16])
	return string(b)
}

// ValidHex128 reports whether id is a valid UUID as returned by Hex128
// and various other UUID packages, such as github.com/satori/go.uuid's
// NewV4 function.
//
// Note that it does not allow upper case hex.
func ValidHex128(id string) bool {
	if len(id) != 36 {
		return false
	}
	if id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	return isValidHex(id[0:8]) &&
		isValidHex(id[9:13]) &&
		isValidHex(id[14:18]) &&
		isValidHex(id[19:23]) &&
		isValidHex(id[24:])
}

func isValidHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}
