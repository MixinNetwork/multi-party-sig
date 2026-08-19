package sample

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/common/params"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingReader fails immediately when read.
type failingReader struct{}

var errFailingReader = errors.New("reader failed")

func (failingReader) Read([]byte) (int, error) {
	return 0, errFailingReader
}

func TestMustReadBits_Panics(t *testing.T) {
	assert.Panics(t, func() {
		mustReadBits(failingReader{}, make([]byte, 8))
	})
}

func TestQNR(t *testing.T) {
	// small Blum-style modulus whose Jacobi behavior is easy to verify
	n := saferith.ModulusFromUint64(3 * 11 * 65519)
	nBig := n.Big()
	for i := 0; i < 32; i++ {
		w := QNR(rand.Reader, n)
		wBig := w.Big()
		if wBig.Cmp(nBig) >= 0 {
			t.Fatalf("QNR out of range: %v", wBig)
		}
		if big.Jacobi(wBig, nBig) != -1 {
			t.Fatalf("QNR has Jacobi symbol != -1: %v", wBig)
		}
	}
}

func TestQNR_Panics(t *testing.T) {
	assert.Panics(t, func() {
		QNR(failingReader{}, saferith.ModulusFromUint64(101))
	})
}

func TestPedersen(t *testing.T) {
	pBig, _ := new(big.Int).SetString("d08769e92f80f7fdfb85ec02affdaed0fde2782070757f191dcdc4d108110ac1e31c07fc253b5f7b91c5d9f203aa0572d3f2062a3d2904c535c6acca7d5674e1c2640720e762c72b66931f483c2d910908cf02ea6723a0cbbb1016ca696c38feac59b31e40584c8141889a11f7a38f5b17811d11f42cd15b8470f11c6183802b", 16)
	qBig, _ := new(big.Int).SetString("c21239c3484fc3c8409f40a9a22fabffe26ca10c27506e3e017c2ec8c4b98d7a6d30ded0686869884be9bad27f5241b7313f73d19e9e4b384fabf9554b5bb4d517cbac0268420c63d545612c9adabeedf20f94244e7f8f2080b0c675ac98d97c580d43375f999b1ac127ec580b89b2d302ef33dd5fd8474a241b0398f6088ca7", 16)
	nBig := new(big.Int).Mul(pBig, qBig)
	n := saferith.ModulusFromNat(new(saferith.Nat).SetBig(nBig, nBig.BitLen()))
	phi := new(big.Int).Mul(new(big.Int).Sub(pBig, big.NewInt(1)), new(big.Int).Sub(qBig, big.NewInt(1)))
	phiNat := new(saferith.Nat).SetBig(phi, phi.BitLen())

	s, tt, lambda := Pedersen(rand.Reader, phiNat, n)

	// s must equal t^lambda mod n
	expected := new(saferith.Nat).Exp(tt, lambda, n)
	require.Equal(t, expected.Eq(s), saferith.Choice(1), "s != t^lambda")

	// t must be a square (hence a QR)
	root := new(saferith.Nat).ModSqrt(tt, n)
	require.NotNil(t, root)
}

func TestScalar(t *testing.T) {
	for _, group := range []curve.Curve{curve.Secp256k1{}, curve.Edwards25519{}} {
		s := Scalar(rand.Reader, group)
		require.NotNil(t, s)

		// the scalar must be < the group order
		b := s.Bytes()
		v := new(big.Int)
		// edwards25519 encodes scalars little-endian, secp256k1 big-endian
		if group.Name() == "edwards25519" {
			le := make([]byte, len(b))
			for i := range b {
				le[i] = b[len(b)-1-i]
			}
			v.SetBytes(le)
		} else {
			v.SetBytes(b)
		}
		assert.True(t, v.Cmp(group.Order().Big()) < 0, group.Name())
	}
}

func TestScalarUnit(t *testing.T) {
	group := curve.Secp256k1{}
	for i := 0; i < 64; i++ {
		s := ScalarUnit(rand.Reader, group)
		require.NotNil(t, s)
		assert.False(t, s.IsZero())
	}
}

func TestScalarPointPair(t *testing.T) {
	group := curve.Secp256k1{}
	s, X := ScalarPointPair(rand.Reader, group)
	require.NotNil(t, s)
	require.NotNil(t, X)
	// X must equal [s]G
	assert.True(t, X.Equal(s.ActOnBase()))
}

func TestIntervals(t *testing.T) {
	tests := []struct {
		name string
		f    func(io.Reader) *saferith.Int
		bits int
	}{
		{"IntervalL", IntervalL, params.L},
		{"IntervalLPrime", IntervalLPrime, params.LPrime},
		{"IntervalEps", IntervalEps, params.Epsilon},
		{"IntervalLEps", IntervalLEps, params.LPlusEpsilon},
		{"IntervalLPrimeEps", IntervalLPrimeEps, params.LPrimePlusEpsilon},
		{"IntervalLN", IntervalLN, params.L + params.BitsIntModN},
		{"IntervalLN2", IntervalLN2, params.L + 2*params.BitsIntModN},
		{"IntervalLEpsN", IntervalLEpsN, params.LPlusEpsilon + params.BitsIntModN},
		{"IntervalLEpsN2", IntervalLEpsN2, params.LPlusEpsilon + 2*params.BitsIntModN},
		{"IntervalLEpsRootN", IntervalLEpsRootN, params.LPlusEpsilon + params.BitsIntModN/2},
	}
	limit := new(big.Int).Lsh(big.NewInt(1), uint(params.LPlusEpsilon+2*params.BitsIntModN+1))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seenPositive, seenNegative := false, false
			for i := 0; i < 16 && !(seenPositive && seenNegative); i++ {
				x := tt.f(rand.Reader)
				abs := x.Abs().Big()
				// |x| < 2^bits
				max := new(big.Int).Lsh(big.NewInt(1), uint(tt.bits))
				assert.True(t, abs.Cmp(max) < 0, "%s out of range", tt.name)
				assert.True(t, abs.Cmp(limit) < 0, "%s above global bound", tt.name)
				if x.IsNegative() == 1 {
					seenNegative = true
				} else {
					seenPositive = true
				}
			}
			assert.True(t, seenPositive && seenNegative, "%s must produce both signs", tt.name)
		})
	}
}

func TestIntervalScalar(t *testing.T) {
	group := curve.Secp256k1{}
	x := IntervalScalar(rand.Reader, group)
	require.NotNil(t, x)
	max := new(big.Int).Lsh(big.NewInt(1), uint(group.ScalarBits()))
	assert.True(t, x.Abs().Big().Cmp(max) < 0)
}

func TestModN_RejectionSampling(t *testing.T) {
	// deterministic reader feeding max-sized values, to exercise the rejection path
	n := saferith.ModulusFromUint64(7)
	maxBytes := make([]byte, 1)
	maxBytes[0] = 0xff
	// first reads produce values >= n, then a valid one
	data := append(bytes.Repeat(maxBytes, 10), 3)
	x := ModN(bytes.NewReader(data), n)
	require.NotNil(t, x)
	assert.Equal(t, uint64(3), x.Uint64())
}

func TestUnitModN_Panics(t *testing.T) {
	// a reader that always returns the same non-unit (0) must exhaust the
	// iteration budget and panic
	assert.Panics(t, func() {
		UnitModN(zeroReader{}, saferith.ModulusFromUint64(101))
	})
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestScalarUnit_Panics(t *testing.T) {
	// a reader yielding only zero scalars must eventually panic
	assert.Panics(t, func() {
		ScalarUnit(zeroReader{}, curve.Secp256k1{})
	})
}
