package polynomial

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExponent_Evaluate(t *testing.T) {
	group := curve.Secp256k1{}

	var lhs curve.Point
	for x := range 5 {
		N := 1000
		secret := group.NewScalar()
		if x%2 == 0 {
			secret = sample.Scalar(rand.Reader, group)
		}
		poly := NewPolynomial(group, N, secret)
		polyExp := NewPolynomialExponent(poly)

		randomIndex := sample.Scalar(rand.Reader, group)

		lhs = poly.Evaluate(randomIndex).ActOnBase()
		rhs1 := polyExp.Evaluate(randomIndex)
		rhs2 := polyExp.evaluateClassic(randomIndex)

		require.Truef(t, lhs.Equal(rhs1), fmt.Sprint("base eval differs from horner", x))
		require.Truef(t, lhs.Equal(rhs2), fmt.Sprint("base eval differs from classic", x))
		require.Truef(t, rhs1.Equal(rhs2), fmt.Sprint("horner differs from classic", x))
	}
}

func TestSum(t *testing.T) {
	group := curve.Secp256k1{}

	N := 20
	Deg := 10

	randomIndex := sample.Scalar(rand.Reader, group)

	// compute f1(x) + f2(x) + …
	evaluationScalar := group.NewScalar()

	// compute F1(x) + F2(x) + …
	evaluationPartial := group.NewPoint()

	polys := make([]*Polynomial, N)
	polysExp := make([]*Exponent, N)
	for i := range polys {
		sec := sample.Scalar(rand.Reader, group)
		polys[i] = NewPolynomial(group, Deg, sec)
		polysExp[i] = NewPolynomialExponent(polys[i])

		evaluationScalar.Add(polys[i].Evaluate(randomIndex))
		evaluationPartial = evaluationPartial.Add(polysExp[i].Evaluate(randomIndex))
	}

	// compute (F1 + F2 + …)(x)
	summedExp, _ := Sum(polysExp)
	evaluationSum := summedExp.Evaluate(randomIndex)

	evaluationFromScalar := evaluationScalar.ActOnBase()
	assert.True(t, evaluationSum.Equal(evaluationFromScalar))
	assert.True(t, evaluationSum.Equal(evaluationPartial))
}

func TestMarshall(t *testing.T) {
	group := curve.Secp256k1{}

	sec := sample.Scalar(rand.Reader, group)
	poly := NewPolynomial(group, 10, sec)
	polyExp := NewPolynomialExponent(poly)
	out, err := cbor.Marshal(polyExp)
	require.NoError(t, err, "failed to Marshal")
	polyExp2 := EmptyExponent(group)
	err = cbor.Unmarshal(out, polyExp2)
	require.NoError(t, err, "failed to Unmarshal")
	assert.True(t, polyExp.Equal(*polyExp2), "should be the same")
}

func TestExponent_UnmarshalBinaryMalformed(t *testing.T) {
	group := curve.Secp256k1{}

	assert.NotPanics(t, func() {
		// short input must return an error, not panic
		e := EmptyExponent(group)
		assert.Error(t, e.UnmarshalBinary(nil))
		assert.Error(t, e.UnmarshalBinary([]byte{1, 2, 3}))

		// a huge claimed coefficient count must be rejected before allocation
		e = EmptyExponent(group)
		data := make([]byte, 4)
		binary.BigEndian.PutUint32(data, 0xFFFFFFFF)
		assert.Error(t, e.UnmarshalBinary(data))

		// a claimed count exceeding what the data can hold must be rejected
		e = EmptyExponent(group)
		data = make([]byte, 64)
		binary.BigEndian.PutUint32(data, 1024)
		assert.Error(t, e.UnmarshalBinary(data))
	})
}
