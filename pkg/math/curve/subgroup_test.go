package curve

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// order8PointHex is a canonical encoding of a point of order 8 on
// edwards25519 (the largest small-order subgroup for cofactor 8).
const order8PointHex = "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"

// leScalar returns the edwards25519 scalar with the given small value, using
// the canonical little-endian encoding (SetNat is unusable for small values
// on edwards25519).
func leScalar(t *testing.T, group Curve, v byte) Scalar {
	t.Helper()
	b := make([]byte, 32)
	b[0] = v
	s := group.NewScalar()
	require.NoError(t, s.UnmarshalBinary(b))
	return s
}

func TestEdwards25519_IsInPrimeOrderGroup(t *testing.T) {
	group := Edwards25519{}
	G := group.NewBasePoint()
	x := randomScalar(t, group)

	// honest points are in the prime-order subgroup
	assert.True(t, G.IsInPrimeOrderGroup())
	assert.True(t, group.NewPoint().IsInPrimeOrderGroup(), "identity is trivially in the subgroup")
	assert.True(t, x.ActOnBase().IsInPrimeOrderGroup())
	assert.True(t, x.Act(G).IsInPrimeOrderGroup())

	// the order-8 torsion point must be rejected
	torsionBytes, err := hex.DecodeString(order8PointHex)
	require.NoError(t, err)
	T8 := group.NewPoint()
	require.NoError(t, T8.UnmarshalBinary(torsionBytes))
	eight := leScalar(t, group, 8)
	four := leScalar(t, group, 4)
	require.True(t, eight.Act(T8).IsIdentity(), "test setup: the point must have order 8")
	assert.False(t, T8.IsIdentity())
	assert.False(t, T8.IsInPrimeOrderGroup())

	// its order-2 multiple must be rejected as well
	T2 := four.Act(T8)
	require.False(t, T2.IsIdentity())
	assert.True(t, four.Act(T2).IsIdentity())
	assert.False(t, T2.IsInPrimeOrderGroup())

	// a prime-order point polluted with torsion must be rejected
	polluted := x.ActOnBase().Add(T8)
	assert.False(t, polluted.IsInPrimeOrderGroup())
	polluted = x.ActOnBase().Add(T2)
	assert.False(t, polluted.IsInPrimeOrderGroup())

	// stripping the torsion with the cofactor lands back in the subgroup
	assert.True(t, eight.Act(polluted).IsInPrimeOrderGroup())
}

func TestSecp256k1_IsInPrimeOrderGroup(t *testing.T) {
	group := Secp256k1{}
	x := randomScalar(t, group)

	// secp256k1 has cofactor 1: every curve point generates the full group
	assert.True(t, group.NewBasePoint().IsInPrimeOrderGroup())
	assert.True(t, group.NewPoint().IsInPrimeOrderGroup())
	assert.True(t, x.ActOnBase().IsInPrimeOrderGroup())
	assert.True(t, x.ActOnBase().Negate().IsInPrimeOrderGroup())
}
