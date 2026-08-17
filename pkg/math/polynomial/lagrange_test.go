package polynomial_test

import (
	"math/big"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/MixinNetwork/multi-party-sig/internal/test"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/polynomial"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
)

func TestLagrange(t *testing.T) {
	group := curve.Secp256k1{}

	N := 10
	allIDs := test.PartyIDs(N)
	coefsEven := polynomial.Lagrange(group, allIDs)
	coefsOdd := polynomial.Lagrange(group, allIDs[:N-1])
	sumEven := group.NewScalar()
	sumOdd := group.NewScalar()
	one := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1))
	for _, c := range coefsEven {
		sumEven.Add(c)
	}
	for _, c := range coefsOdd {
		sumOdd.Add(c)
	}
	assert.True(t, sumEven.Equal(one))
	assert.True(t, sumOdd.Equal(one))
}

func TestLagrangePanicsOnInvalidDomain(t *testing.T) {
	group := curve.Secp256k1{}
	q := group.Order().Nat().Big()

	// two distinct party IDs mapping to the same evaluation point
	aliased := new(big.Int).Add(big.NewInt(42), q)
	collidingIDs := []party.ID{
		party.ID(string(big.NewInt(42).Bytes())),
		party.ID(string(aliased.Bytes())),
		party.ID("c"),
	}
	assert.Panics(t, func() { polynomial.Lagrange(group, collidingIDs) })

	// a party ID mapping to the zero evaluation point
	zeroIDs := []party.ID{
		party.ID(string(q.Bytes())),
		party.ID("b"),
		party.ID("c"),
	}
	assert.Panics(t, func() { polynomial.Lagrange(group, zeroIDs) })
}
