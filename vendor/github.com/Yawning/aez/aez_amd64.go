// aez_amd64.go - AMD64 specific routines.
//
// To the extent possible under law, Yawning Angel has waived all copyright
// and related or neighboring rights to aez, using the Creative
// Commons "CC0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

// +build amd64,!gccgo,!appengine,!noasm

package aez

var useAESNI = false

//go:noescape
func cpuidAMD64(cpuidParams *uint32)

//go:noescape
func resetAMD64SSE2()

//go:noescape
func xorBytes1x16AMD64SSE2(a, b, dst *byte)

//go:noescape
func xorBytes4x16AMD64SSE2(a, b, c, d, dst *byte)

//go:noescape
func aezAES4AMD64AESNI(j, i, l, k, src, dst *byte)

//go:noescape
func aezAES10AMD64AESNI(l, k, src, dst *byte)

//go:noescape
func aezCorePass1AMD64AESNI(src, dst, x, i, l, k, consts *byte, sz int)

//go:noescape
func aezCorePass2AMD64AESNI(dst, y, s, j, i, l, k, consts *byte, sz int)

func xorBytes1x16(a, b, dst []byte) {
	xorBytes1x16AMD64SSE2(&a[0], &b[0], &dst[0])
}

func xorBytes4x16(a, b, c, d, dst []byte) {
	xorBytes4x16AMD64SSE2(&a[0], &b[0], &c[0], &d[0], &dst[0])
}

type roundAESNI struct {
	keys [extractedKeySize]byte
}

func (r *roundAESNI) Reset() {
	memwipe(r.keys[:])
	resetAMD64SSE2()
}

func (r *roundAESNI) AES4(j, i, l *[blockSize]byte, src []byte, dst *[blockSize]byte) {
	aezAES4AMD64AESNI(&j[0], &i[0], &l[0], &r.keys[0], &src[0], &dst[0])
}

func (r *roundAESNI) AES10(l *[blockSize]byte, src []byte, dst *[blockSize]byte) {
	aezAES10AMD64AESNI(&l[0], &r.keys[0], &src[0], &dst[0])
}

func newRoundAESNI(extractedKey *[extractedKeySize]byte) aesImpl {
	r := new(roundAESNI)
	copy(r.keys[:], extractedKey[:])

	return r
}

var dblConsts = [32]byte{
	// PSHUFB constant
	0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
	0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,

	// Mask constant
	0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x87, 0x00, 0x00, 0x00,
}

func (e *eState) aezCorePass1(in, out []byte, X *[blockSize]byte, sz int) {
	// Call the "slow" implementation if hardware/OS doesn't allow AES-NI.
	if !useAESNI {
		e.aezCorePass1Slow(in, out, X, sz)
		return
	}

	// Call the AES-NI implementation.
	a := e.aes.(*roundAESNI)
	aezCorePass1AMD64AESNI(&in[0], &out[0], &X[0], &e.I[1][0], &e.L[0][0], &a.keys[0], &dblConsts[0], sz)
}

func (e *eState) aezCorePass2(in, out []byte, Y, S *[blockSize]byte, sz int) {
	// Call the "slow" implementation if hardware/OS doesn't allow AES-NI.
	if !useAESNI {
		e.aezCorePass2Slow(in, out, Y, S, sz)
		return
	}

	// Call the AES-NI implementation.
	a := e.aes.(*roundAESNI)
	aezCorePass2AMD64AESNI(&out[0], &Y[0], &S[0], &e.J[0][0], &e.I[1][0], &e.L[0][0], &a.keys[0], &dblConsts[0], sz)
}

func supportsAESNI() bool {
	const aesniBit = 1 << 25

	// Check for AES-NI support.
	// CPUID.(EAX=01H, ECX=0H):ECX.AESNI[bit 25]==1
	regs := [4]uint32{0x01}
	cpuidAMD64(&regs[0])

	return regs[2]&aesniBit != 0
}

func platformInit() {
	useAESNI = supportsAESNI()
	if useAESNI {
		newAes = newRoundAESNI
		isHardwareAccelerated = true
	}
}
