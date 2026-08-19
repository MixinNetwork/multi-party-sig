package bip32

import (
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func basePoint(t *testing.T) *curve.Secp256k1Point {
	t.Helper()
	group := curve.Secp256k1{}
	return group.NewScalar().
		SetNat(new(saferith.Nat).SetUint64(42)).
		ActOnBase().(*curve.Secp256k1Point)
}

func TestDeriveScalar(t *testing.T) {
	public := basePoint(t)
	chaining := make([]byte, 32)
	for i := range chaining {
		chaining[i] = byte(i)
	}

	scalar, chain, err := DeriveScalar(public, chaining, 0)
	require.NoError(t, err)
	require.NotNil(t, scalar)
	require.Len(t, chain, 32)
	assert.False(t, scalar.IsZero())

	// determinism
	scalar2, chain2, err := DeriveScalar(public, chaining, 0)
	require.NoError(t, err)
	assert.True(t, scalar.Equal(scalar2))
	assert.Equal(t, chain, chain2)

	// different indices yield different scalars
	scalar3, chain3, err := DeriveScalar(public, chaining, 1)
	require.NoError(t, err)
	assert.False(t, scalar.Equal(scalar3))
	assert.NotEqual(t, chain, chain3)

	// different chaining values yield different scalars
	chaining2 := make([]byte, 32)
	copy(chaining2, chaining)
	chaining2[0] ^= 1
	scalar4, _, err := DeriveScalar(public, chaining2, 0)
	require.NoError(t, err)
	assert.False(t, scalar.Equal(scalar4))

	// different public keys yield different scalars
	public2 := basePoint(t)
	public2 = curve.Secp256k1{}.NewScalar().
		SetNat(new(saferith.Nat).SetUint64(43)).
		ActOnBase().(*curve.Secp256k1Point)
	scalar5, _, err := DeriveScalar(public2, chaining, 0)
	require.NoError(t, err)
	assert.False(t, scalar.Equal(scalar5))
}

func TestDeriveScalar_PanicsOnHardened(t *testing.T) {
	public := basePoint(t)
	assert.Panics(t, func() {
		_, _, _ = DeriveScalar(public, make([]byte, 32), 1<<31)
	})
}
