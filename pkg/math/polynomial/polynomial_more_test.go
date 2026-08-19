package polynomial

import (
	"bytes"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var polyGroups = []curve.Curve{curve.Secp256k1{}, curve.Edwards25519{}}

func TestPolynomial_DegreeAndNilConstant(t *testing.T) {
	for _, group := range polyGroups {
		// a nil constant is interpreted as zero
		p := NewPolynomial(group, 3, nil)
		assert.Equal(t, uint32(3), p.Degree(), group.Name())
		assert.True(t, p.Constant().IsZero(), group.Name())

		// the secret constant is preserved
		secret := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(42))
		p2 := NewPolynomial(group, 2, secret)
		assert.Equal(t, uint32(2), p2.Degree())
		assert.True(t, p2.Constant().Equal(secret))

		// Constant returns a copy
		c := p2.Constant()
		c.Add(secret)
		assert.True(t, p2.Constant().Equal(secret), "Constant must return a copy")
	}
}

func TestPolynomial_EvaluatePanicsOnZero(t *testing.T) {
	for _, group := range polyGroups {
		p := NewPolynomial(group, 1, group.NewScalar().SetNat(new(saferith.Nat).SetUint64(7)))
		assert.Panics(t, func() {
			p.Evaluate(group.NewScalar())
		}, group.Name())
	}
}

func TestExponent_DegreeAndConstant(t *testing.T) {
	for _, group := range polyGroups {
		// constant term zero
		p := NewPolynomial(group, 2, group.NewScalar())
		exp := NewPolynomialExponent(p)
		assert.Equal(t, 2, exp.Degree(), group.Name())
		assert.True(t, exp.Constant().IsIdentity(), group.Name())

		// non-zero constant
		secret := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(11))
		p2 := NewPolynomial(group, 2, secret)
		exp2 := NewPolynomialExponent(p2)
		assert.Equal(t, 2, exp2.Degree())
		assert.True(t, exp2.Constant().Equal(secret.ActOnBase()))
	}
}

func TestExponent_EqualAndSumErrors(t *testing.T) {
	group := curve.Secp256k1{}
	p1 := NewPolynomialExponent(NewPolynomial(group, 2, group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1))))
	p2 := NewPolynomialExponent(NewPolynomial(group, 2, group.NewScalar().SetNat(new(saferith.Nat).SetUint64(2))))
	p3 := NewPolynomialExponent(NewPolynomial(group, 3, group.NewScalar().SetNat(new(saferith.Nat).SetUint64(3))))
	pConst := NewPolynomialExponent(NewPolynomial(group, 2, group.NewScalar()))

	assert.True(t, p1.Equal(*p1))
	assert.False(t, p1.Equal(*p2))
	// different lengths
	assert.False(t, p1.Equal(*p3))
	// different IsConstant flags
	assert.False(t, p1.Equal(*pConst))

	// Sum with mismatched lengths must fail
	_, err := Sum([]*Exponent{p1, p3})
	assert.Error(t, err)

	// Sum with mismatched IsConstant must fail
	_, err = Sum([]*Exponent{p1, pConst})
	assert.Error(t, err)

	// Sum of compatible polynomials succeeds
	sum, err := Sum([]*Exponent{p1, p2})
	require.NoError(t, err)
	// the constant terms add up
	expected := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1)).
		Add(group.NewScalar().SetNat(new(saferith.Nat).SetUint64(2))).ActOnBase()
	assert.True(t, sum.Constant().Equal(expected))

	// Sum of a single polynomial returns a copy
	single, err := Sum([]*Exponent{p1})
	require.NoError(t, err)
	assert.True(t, single.Equal(*p1))
}

func TestExponent_WriteToAndDomain(t *testing.T) {
	group := curve.Secp256k1{}
	p := NewPolynomialExponent(NewPolynomial(group, 1, group.NewScalar().SetNat(new(saferith.Nat).SetUint64(5))))

	var buf bytes.Buffer
	n, err := p.WriteTo(&buf)
	require.NoError(t, err)
	assert.Equal(t, int64(buf.Len()), n)
	assert.Positive(t, buf.Len())
	assert.Equal(t, "Exponent", p.Domain())
}

func TestLagrangeSingle(t *testing.T) {
	for _, group := range polyGroups {
		ids := party.IDSlice{"a", "b", "c"}
		// the single coefficient must match the full map
		single := LagrangeSingle(group, ids, "b")
		full := Lagrange(group, ids)
		assert.True(t, single.Equal(full["b"]), group.Name())
	}
}

func TestLagrange_Panics(t *testing.T) {
	group := curve.Secp256k1{}
	// a zero evaluation point must panic (it would address the secret itself)
	zeroID := party.ID(string([]byte{0}))
	assert.Panics(t, func() {
		Lagrange(group, party.IDSlice{"a", zeroID})
	})
}

func TestExponent_UnmarshalErrors(t *testing.T) {
	group := curve.Secp256k1{}

	// no group set
	e := &Exponent{}
	assert.Error(t, e.UnmarshalBinary([]byte{0, 0, 0, 1}))

	// too short
	e = EmptyExponent(group)
	assert.Error(t, e.UnmarshalBinary([]byte{0, 0}))

	// an impossible length prefix must be rejected without allocating
	e = EmptyExponent(group)
	huge := []byte{0xff, 0xff, 0xff, 0xff}
	assert.Error(t, e.UnmarshalBinary(huge))
}
