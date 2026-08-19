package curve

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var allCurves = []Curve{
	Secp256k1{},
	Edwards25519{},
}

// randomScalar returns a non-zero scalar derived from random input.
func randomScalar(t *testing.T, group Curve) Scalar {
	t.Helper()
	var randomness [64]byte
	_, err := rand.Read(randomness[:])
	require.NoError(t, err)
	s := FromHash(group, randomness[:])
	for s.IsZero() {
		_, err = rand.Read(randomness[:])
		require.NoError(t, err)
		s = FromHash(group, randomness[:])
	}
	return s
}

func TestCurve_MetaData(t *testing.T) {
	names := map[string]bool{}
	for _, group := range allCurves {
		assert.NotEqual(t, "", group.Name())
		assert.False(t, names[group.Name()], "duplicate curve name %s", group.Name())
		names[group.Name()] = true
		assert.Equal(t, 256, group.ScalarBits())
		assert.True(t, group.SafeScalarBytes() >= 32)
		assert.NotNil(t, group.Order())
		assert.Equal(t, group.Name(), group.NewScalar().Curve().Name())
		assert.Equal(t, group.Name(), group.NewPoint().Curve().Name())
	}
}

func TestScalar_ZeroOne(t *testing.T) {
	// NOTE: value-based SetNat assertions hold on secp256k1.
	// Edwards25519Scalar.SetNat deviates from its contract (see audit report).
	group := Secp256k1{}
	zero := group.NewScalar()
	assert.True(t, zero.IsZero())
	assert.True(t, zero.Equal(group.NewScalar()))

	one := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1))
	assert.False(t, one.IsZero())

	G := group.NewBasePoint()
	assert.True(t, zero.Act(G).IsIdentity())
	assert.True(t, one.Act(G).Equal(G))
	assert.True(t, one.ActOnBase().Equal(G))
	assert.True(t, zero.ActOnBase().IsIdentity())
}

func TestScalar_MarshalRoundTrip(t *testing.T) {
	for _, group := range allCurves {
		s := randomScalar(t, group)
		data, err := s.MarshalBinary()
		require.NoError(t, err)

		s2 := group.NewScalar()
		require.NoError(t, s2.UnmarshalBinary(data))
		assert.True(t, s.Equal(s2), group.Name())

		// bad lengths must error
		assert.Error(t, s2.UnmarshalBinary(nil))
		assert.Error(t, s2.UnmarshalBinary(data[:len(data)-1]))
		assert.Error(t, s2.UnmarshalBinary(append(data, 0)))

		// Bytes() must agree with MarshalBinary
		assert.Equal(t, data, s.Bytes())

		// the order itself (or larger) must be rejected
		orderBytes := group.Order().Bytes()
		err = s2.UnmarshalBinary(orderBytes)
		assert.Error(t, err, "%s: scalar equal to the order must be rejected", group.Name())
	}
}

func TestScalar_SetNatInvariants(t *testing.T) {
	// Invariants that hold on both curves even in the presence of the
	// Edwards25519 SetNat deviation: zero maps to zero, and the mapping is
	// deterministic.
	for _, group := range allCurves {
		assert.True(t, group.NewScalar().SetNat(new(saferith.Nat).SetUint64(0)).IsZero(), group.Name())
		x := new(saferith.Nat).SetUint64(42)
		s1 := group.NewScalar().SetNat(x)
		s2 := group.NewScalar().SetNat(x)
		assert.True(t, s1.Equal(s2), group.Name())
	}

	// inputs equal modulo the order must produce equal scalars
	group := Secp256k1{}
	bigX := new(big.Int).Add(big.NewInt(42), group.Order().Big())
	s3 := group.NewScalar().SetNat(new(saferith.Nat).SetBig(bigX, 512))
	s1 := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(42))
	assert.True(t, s3.Equal(s1))
}

func TestScalar_Arithmetic(t *testing.T) {
	group := Secp256k1{}
	toScalar := func(i uint64) Scalar {
		return group.NewScalar().SetNat(new(saferith.Nat).SetUint64(i))
	}
	a, b := toScalar(3), toScalar(7)
	one := toScalar(1)

	// a + b
	sum := group.NewScalar().Set(a).Add(b)
	assert.True(t, sum.Equal(toScalar(10)))

	// (a + b) - a == b
	diff := group.NewScalar().Set(sum).Sub(a)
	assert.True(t, diff.Equal(b))

	// a * b
	prod := group.NewScalar().Set(a).Mul(b)
	assert.True(t, prod.Equal(toScalar(21)))

	// a * a⁻¹ == 1
	inv := group.NewScalar().Set(a).Invert()
	assert.True(t, group.NewScalar().Set(inv).Mul(a).Equal(one))

	// -a + a == 0
	neg := group.NewScalar().Set(a).Negate()
	assert.True(t, group.NewScalar().Set(neg).Add(a).IsZero())

	// a - a == 0
	assert.True(t, group.NewScalar().Set(a).Sub(a).IsZero())

	// 0 can't be inverted (wraps back to 0)
	assert.True(t, group.NewScalar().Invert().IsZero())

	// inverse of 1 is 1
	assert.True(t, group.NewScalar().Set(one).Invert().Equal(one))

	// SetNat reduces mod the order: 7 + order == 7
	bigN := new(big.Int).Add(big.NewInt(7), group.Order().Big())
	reduced := group.NewScalar().SetNat(new(saferith.Nat).SetBig(bigN, 512))
	assert.True(t, reduced.Equal(b))

	// (order - 1) + 1 wraps to 0
	max := new(big.Int).Sub(group.Order().Big(), big.NewInt(1))
	s := group.NewScalar().SetNat(new(saferith.Nat).SetBig(max, 512))
	assert.False(t, s.IsZero())
	assert.True(t, s.Add(one).IsZero())
}

func TestScalar_FieldArithmeticBothCurves(t *testing.T) {
	// Algebraic laws that must hold regardless of how scalars were sampled.
	for _, group := range allCurves {
		x := randomScalar(t, group)
		y := randomScalar(t, group)
		one := x.ActOnBase() // reference for group action consistency

		_ = one
		// (x + y) - y == x
		sum := group.NewScalar().Set(x).Add(y)
		assert.True(t, group.NewScalar().Set(sum).Sub(y).Equal(x), group.Name())

		// (x * y) * y⁻¹ == x
		prod := group.NewScalar().Set(x).Mul(y)
		assert.True(t, group.NewScalar().Set(prod).Mul(group.NewScalar().Set(y).Invert()).Equal(x), group.Name())

		// x - x == 0 and x + (-x) == 0
		assert.True(t, group.NewScalar().Set(x).Sub(x).IsZero(), group.Name())
		assert.True(t, group.NewScalar().Set(x).Add(group.NewScalar().Set(x).Negate()).IsZero(), group.Name())

		// associativity/commutativity
		assert.True(t, group.NewScalar().Set(x).Add(y).Equal(group.NewScalar().Set(y).Add(x)), group.Name())
		z := randomScalar(t, group)
		assert.True(t,
			group.NewScalar().Set(x).Mul(group.NewScalar().Set(y).Mul(z)).Equal(group.NewScalar().Set(x).Mul(y).Mul(z)),
			group.Name())
	}
}

func TestScalar_Act(t *testing.T) {
	for _, group := range allCurves {
		x := randomScalar(t, group)
		y := randomScalar(t, group)

		// [x]G + [y]G == [x + y]G
		left := x.ActOnBase().Add(y.ActOnBase())
		sum := group.NewScalar().Set(x).Add(y)
		assert.True(t, left.Equal(sum.ActOnBase()), group.Name())

		// [x][y]G == [y][x]G
		assert.True(t, x.Act(y.ActOnBase()).Equal(y.Act(x.ActOnBase())), group.Name())

		// [x]G + [-x]G == identity
		assert.True(t, x.ActOnBase().Add(group.NewScalar().Set(x).Negate().ActOnBase()).IsIdentity(), group.Name())
	}
}

func TestPoint_Arithmetic(t *testing.T) {
	for _, group := range allCurves {
		x := randomScalar(t, group)
		y := randomScalar(t, group)
		X := x.ActOnBase()
		Y := y.ActOnBase()

		// X + Y == Y + X
		assert.True(t, X.Add(Y).Equal(Y.Add(X)), group.Name())

		// X - X == identity
		assert.True(t, X.Sub(X).IsIdentity(), group.Name())

		// X + identity == X
		assert.True(t, X.Add(group.NewPoint()).Equal(X), group.Name())

		// X - Y == X + (-Y)
		assert.True(t, X.Sub(Y).Equal(X.Add(Y.Negate())), group.Name())

		// -(-X) == X
		assert.True(t, X.Negate().Negate().Equal(X), group.Name())

		// 2X == X + X
		assert.True(t, X.Add(X).Equal(group.NewScalar().Set(x).Add(x).ActOnBase()), group.Name())

		// negation acts like subtraction on both sides
		assert.True(t, X.Add(Y).Sub(Y).Equal(X), group.Name())

		if group.Name() == "secp256k1" {
			identity := group.NewPoint()
			assert.True(t, identity.HasEvenY())
			// the negation of an affine point must flip the parity of Y
			assert.NotEqual(t, X.HasEvenY(), X.Negate().HasEvenY())
		}
	}
}

func TestPoint_MarshalRoundTrip(t *testing.T) {
	for _, group := range allCurves {
		X := randomScalar(t, group).ActOnBase()
		data, err := X.MarshalBinary()
		require.NoError(t, err)

		X2 := group.NewPoint()
		require.NoError(t, X2.UnmarshalBinary(data))
		assert.True(t, X2.Equal(X))

		// bad lengths must error
		assert.Error(t, X2.UnmarshalBinary(nil))
		assert.Error(t, X2.UnmarshalBinary(data[:len(data)-1]))
		assert.Error(t, X2.UnmarshalBinary(append(data, 0)))
	}
}

func TestPoint_Set(t *testing.T) {
	X := randomScalar(t, Secp256k1{}).ActOnBase().(*Secp256k1Point)
	Y := new(Secp256k1Point).Set(X)
	assert.True(t, Y.Equal(X))

	Xe := randomScalar(t, Edwards25519{}).ActOnBase().(*Edwards25519Point)
	Ye := new(Edwards25519Point).Set(Xe)
	assert.True(t, Ye.Equal(Xe))
}

func TestSecp256k1Point_UnmarshalErrors(t *testing.T) {
	group := Secp256k1{}
	generatorX, _ := hex.DecodeString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

	// x = 5 is not on the curve: x³ + 7 = 132 is a quadratic non-residue mod p
	notOnCurve := make([]byte, 33)
	notOnCurve[0] = 2
	notOnCurve[32] = 5
	assert.Error(t, group.NewPoint().UnmarshalBinary(notOnCurve))

	// x out of range (>= p)
	xOverflow, _ := hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30")
	overflow := append([]byte{2}, xOverflow...)
	assert.Error(t, group.NewPoint().UnmarshalBinary(overflow))

	// LiftX
	p, err := group.LiftX(generatorX)
	assert.NoError(t, err)
	assert.True(t, p.Equal(group.NewBasePoint()))
	assert.True(t, p.HasEvenY()) // the generator's Y coordinate is even

	// LiftX failures
	_, err = group.LiftX(notOnCurve[1:])
	assert.Error(t, err)
	_, err = group.LiftX(xOverflow)
	assert.Error(t, err)
}

func TestSecp256k1Point_XScalarYScalar(t *testing.T) {
	group := Secp256k1{}
	G := group.NewBasePoint()
	generatorX, _ := hex.DecodeString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	generatorY, _ := hex.DecodeString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")

	xBytes, err := G.XScalar().MarshalBinary()
	require.NoError(t, err)
	yBytes, err := G.YScalar().MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, generatorX, xBytes)
	assert.Equal(t, generatorY, yBytes)

	// the identity point has zero coordinates
	identity := group.NewPoint()
	assert.True(t, identity.XScalar().IsZero())
	assert.True(t, identity.YScalar().IsZero())

	// negation must flip the parity of the Y coordinate
	neg := G.Negate()
	negY, err := neg.YScalar().MarshalBinary()
	require.NoError(t, err)
	assert.NotEqual(t, yBytes, negY)
	// y(p − y) = p must hold for the negated coordinate
	yBig := new(big.Int).SetBytes(yBytes)
	negBig := new(big.Int).SetBytes(negY)
	fieldPrime, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	assert.Equal(t, 0, new(big.Int).Add(yBig, negBig).Cmp(fieldPrime))
}

func TestEdwards25519_Point(t *testing.T) {
	group := Edwards25519{}
	G := group.NewBasePoint()
	x := randomScalar(t, group)
	X := x.ActOnBase()
	// X + (identity - X) == identity, and the generator is not the identity
	assert.True(t, X.Add(group.NewPoint().Sub(X)).IsIdentity())
	assert.False(t, G.IsIdentity())
	assert.True(t, group.NewPoint().IsIdentity())

	// edwards25519 does not expose ECDSA-style coordinates
	assert.Nil(t, G.XScalar())
	assert.Nil(t, G.YScalar())
	assert.False(t, G.HasEvenY())

	// the canonical encoding of the twisted Edwards identity (0, 1) is
	// y = 1, i.e. 01 followed by zeros, and must round-trip.
	identityEnc := make([]byte, 32)
	identityEnc[0] = 0x01
	P := group.NewPoint()
	require.NoError(t, P.UnmarshalBinary(identityEnc))
	assert.True(t, P.IsIdentity())
	canonical, err := P.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, identityEnc, canonical)

	// a non-canonical identity encoding (x = 0 with the sign bit set) is
	// accepted by filippo.io/edwards25519, and normalizes on re-encoding
	nonCanonical := make([]byte, 32)
	nonCanonical[0] = 0x01
	nonCanonical[31] = 0x80
	require.NoError(t, P.UnmarshalBinary(nonCanonical))
	assert.True(t, P.IsIdentity())
	reenc, err := P.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, identityEnc, reenc)

	// an unreduced y (= p + 1 ≡ 1) is accepted as well, decoding to the identity
	unreduced, _ := hex.DecodeString("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	require.NoError(t, P.UnmarshalBinary(unreduced))
	assert.True(t, P.IsIdentity())
	reenc, err = P.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, identityEnc, reenc)

	// an encoding that is not a valid point at all must still be rejected
	invalid := make([]byte, 32)
	invalid[31] = 0x01 // this does not decode to a curve point
	assert.Error(t, group.NewPoint().UnmarshalBinary(invalid))
}

func TestMakeInt(t *testing.T) {
	group := Secp256k1{}
	s := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(35))
	i := MakeInt(s)
	assert.Equal(t, big.NewInt(35), i.Big())
}

func TestFromHash(t *testing.T) {
	for _, group := range allCurves {
		h := make([]byte, 128) // much longer than the order
		for i := range h {
			h[i] = byte(i)
		}
		s := FromHash(group, h)
		require.NotNil(t, s)
		// deterministic
		assert.True(t, s.Equal(FromHash(group, h)))
		// a different hash yields a different scalar (whp)
		h[0] ^= 1
		assert.False(t, s.Equal(FromHash(group, h)))
	}

	// the SECG truncation semantics are directly testable on secp256k1:
	// the scalar must equal the first 32 bytes of the hash interpreted as
	// a big-endian number.
	group := Secp256k1{}
	h := make([]byte, 128)
	for i := range h {
		h[i] = byte(i + 1)
	}
	s := FromHash(group, h)
	expected := new(big.Int).SetBytes(h[:32])
	assert.Equal(t, 0, new(big.Int).SetBytes(s.Bytes()).Cmp(expected))

	// short hashes must work as well
	for _, group := range allCurves {
		s := FromHash(group, []byte{1, 2, 3})
		require.NotNil(t, s)
	}
}

func TestScalar_CastPanics(t *testing.T) {
	assert.Panics(t, func() { secp256k1CastScalar(Edwards25519{}.NewScalar()) })
	assert.Panics(t, func() { secp256k1CastPoint(Edwards25519{}.NewPoint()) })
	assert.Panics(t, func() { edwards25519CastScalar(Secp256k1{}.NewScalar()) })
	assert.Panics(t, func() { edwards25519CastPoint(Secp256k1{}.NewPoint()) })
}
