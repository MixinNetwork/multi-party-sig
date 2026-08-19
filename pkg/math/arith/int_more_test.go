package arith

import (
	"math/big"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/common/params"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
)

func fromInt64(x int64) *saferith.Int {
	i := new(big.Int).SetInt64(x)
	return new(saferith.Int).SetBig(i, i.BitLen())
}

func TestIsValidBigModN(t *testing.T) {
	N := big.NewInt(3 * 11 * 101) // 3333

	assert.True(t, IsValidBigModN(N, big.NewInt(2)))
	assert.True(t, IsValidBigModN(N, big.NewInt(7), big.NewInt(169)))

	// nil values are rejected
	assert.False(t, IsValidBigModN(N, nil))

	// zero, negatives and N or above are rejected
	assert.False(t, IsValidBigModN(N, big.NewInt(0)))
	assert.False(t, IsValidBigModN(N, big.NewInt(-1)))
	assert.False(t, IsValidBigModN(N, N))
	assert.False(t, IsValidBigModN(N, new(big.Int).Add(N, big.NewInt(1))))

	// non-coprime values are rejected
	assert.False(t, IsValidBigModN(N, big.NewInt(3)))
	assert.False(t, IsValidBigModN(N, big.NewInt(11)))
	assert.False(t, IsValidBigModN(N, big.NewInt(303)))
}

func TestIntervals(t *testing.T) {
	// boundary helpers
	lEps := new(big.Int).Lsh(big.NewInt(1), uint(params.LPlusEpsilon))
	lPrimeEps := new(big.Int).Lsh(big.NewInt(1), uint(params.LPrimePlusEpsilon))
	rootNBound := new(big.Int).Lsh(big.NewInt(1), uint(1+params.LPlusEpsilon+params.BitsIntModN/2))

	tests := []struct {
		name   string
		check  func(*saferith.Int) bool
		bound  *big.Int
		bitsOf int
	}{
		{"LEps", IsInIntervalLEps, lEps, params.LPlusEpsilon},
		{"LPrimeEps", IsInIntervalLPrimeEps, lPrimeEps, params.LPrimePlusEpsilon},
		{"LEpsPlus1RootN", IsInIntervalLEpsPlus1RootN, rootNBound, 1 + params.LPlusEpsilon + params.BitsIntModN/2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// nil is rejected
			assert.False(t, tt.check(nil))

			// zero and small values are inside
			assert.True(t, tt.check(fromInt64(0)))
			assert.True(t, tt.check(fromInt64(1)))
			assert.True(t, tt.check(fromInt64(-1)))

			// the boundary 2^bits itself is outside, since TrueLen > bits
			boundary := new(big.Int).Lsh(big.NewInt(1), uint(tt.bitsOf))
			assert.False(t, tt.check(new(saferith.Int).SetBig(boundary, boundary.BitLen())),
				"boundary 2^%d must be outside", tt.bitsOf)
			negBoundary := new(big.Int).Neg(boundary)
			assert.False(t, tt.check(new(saferith.Int).SetBig(negBoundary, negBoundary.BitLen())))

			// just below the boundary is inside
			inside := new(big.Int).Sub(boundary, big.NewInt(1))
			assert.True(t, tt.check(new(saferith.Int).SetBig(inside, inside.BitLen())))
		})
	}
}

func TestIsValidIntLen_Boundaries(t *testing.T) {
	assert.False(t, IsValidIntLen(nil))
	assert.True(t, IsValidIntLen(fromInt64(0)))
	assert.True(t, IsValidIntLen(fromInt64(-42)))

	// a value exactly at the bound is accepted
	atBound := new(big.Int).Lsh(big.NewInt(1), MaxIntResponseBits-1)
	assert.True(t, IsValidIntLen(new(saferith.Int).SetBig(atBound, MaxIntResponseBits)))

	// one bit above is rejected (announced length)
	over := new(big.Int).Lsh(big.NewInt(1), MaxIntResponseBits)
	assert.False(t, IsValidIntLen(new(saferith.Int).SetBig(over, MaxIntResponseBits+1)))
}

func TestIsValidNatModN_AnnouncedLenSlack(t *testing.T) {
	// a Nat with an inflated announced length must be rejected even if its
	// value is in range
	N := saferith.ModulusFromUint64(101)
	x := new(saferith.Nat).SetUint64(7)
	x.Resize(N.BitLen() + maxAnnouncedSlack + 128)
	assert.False(t, IsValidNatModN(N, x))
}
