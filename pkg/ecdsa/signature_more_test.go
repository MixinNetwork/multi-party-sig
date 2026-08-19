package ecdsa

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/cronokirby/saferith"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmptySignature(t *testing.T) {
	group := curve.Secp256k1{}
	sig := EmptySignature(group)
	assert.NotNil(t, sig.R)
	assert.NotNil(t, sig.S)
	assert.True(t, sig.R.IsIdentity())
	assert.True(t, sig.S.IsZero())
}

func TestSignature_Serialize_Parse_RoundTrip(t *testing.T) {
	group := curve.Secp256k1{}
	m := []byte("serialization")
	x := sample.Scalar(rand.Reader, group)
	sig := NewSignature(x, m, nil)

	data := sig.Serialize()
	require.Len(t, data, 65)

	parsed, err := ParseSignature(group, data)
	require.NoError(t, err)
	assert.True(t, parsed.R.Equal(sig.R))
	assert.True(t, parsed.S.Equal(sig.S))

	// the parsed signature must still verify
	X := x.ActOnBase()
	assert.True(t, parsed.Verify(X, m))

	// invalid lengths must be rejected
	_, err = ParseSignature(group, nil)
	assert.Error(t, err)
	_, err = ParseSignature(group, data[:64])
	assert.Error(t, err)
	_, err = ParseSignature(group, append(data, 0))
	assert.Error(t, err)

	// invalid point bytes must be rejected
	bad := make([]byte, 65)
	copy(bad, data)
	bad[0] = 0x04 // invalid prefix
	_, err = ParseSignature(group, bad)
	assert.Error(t, err)

	// invalid scalar bytes must be rejected
	bad = make([]byte, 65)
	copy(bad, data)
	copy(bad[33:], group.Order().Bytes())
	_, err = ParseSignature(group, bad)
	assert.Error(t, err)
}

func TestSignature_Verify_WrongKeyOrMessage(t *testing.T) {
	group := curve.Secp256k1{}
	m := []byte("message")
	other := []byte("other message")
	x := sample.Scalar(rand.Reader, group)
	X := x.ActOnBase()
	y := sample.Scalar(rand.Reader, group)
	Y := y.ActOnBase()

	sig := NewSignature(x, m, nil)
	assert.True(t, sig.Verify(X, m))
	// wrong public key
	assert.False(t, sig.Verify(Y, m))
	// wrong message
	assert.False(t, sig.Verify(X, other))
}

func TestSignature_SerializeDER(t *testing.T) {
	group := curve.Secp256k1{}
	m := []byte("der encoding")
	x := sample.Scalar(rand.Reader, group)
	sig := NewSignature(x, m, nil)

	der := sig.SerializeDER()

	// parse the DER encoding back with the reference implementation
	parsed, err := ecdsa.ParseDERSignature(der)
	require.NoError(t, err)
	rVal, sVal := parsed.R(), parsed.S()
	rBytes, sBytes := rVal.Bytes(), sVal.Bytes()

	// r must equal the x coordinate of R, and s must equal the signature's
	// S (or its low-S normalization)
	rScalar := group.NewScalar()
	require.NoError(t, rScalar.UnmarshalBinary(rBytes[:]))
	rx, err := sig.R.XScalar().MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, rx, rBytes[:])

	sScalar := group.NewScalar()
	require.NoError(t, sScalar.UnmarshalBinary(sBytes[:]))
	sNeg := group.NewScalar().Set(sig.S).Negate()
	sNegBytes, err := sNeg.MarshalBinary()
	require.NoError(t, err)
	_ = sNegBytes
	if !assert.True(t, sScalar.Equal(sig.S) || sScalar.Equal(sNeg)) {
		t.Logf("parsed s does not match original or its negation")
	}
}

// recoverEth recovers the public key from a (r ‖ s ‖ v) ethereum-style
// signature over hash m, via X = r⁻¹(sR − mG).
func recoverEth(t *testing.T, group curve.Secp256k1, eth []byte, v byte, m []byte) curve.Point {
	t.Helper()
	r := group.NewScalar()
	if err := r.UnmarshalBinary(eth[:32]); err != nil {
		return nil
	}
	s := group.NewScalar()
	if err := s.UnmarshalBinary(eth[32:64]); err != nil {
		return nil
	}
	R := group.NewPoint()
	buf := append([]byte{2 + v}, eth[:32]...)
	if err := R.UnmarshalBinary(buf); err != nil {
		return nil
	}
	mScalar := curve.FromHash(group, m)
	rInv := group.NewScalar().Set(r).Invert()
	return rInv.Act(s.Act(R).Sub(mScalar.ActOnBase()))
}

func TestSignature_SerializeEthereum(t *testing.T) {
	group := curve.Secp256k1{}
	m := []byte("ethereum encoding")
	x := sample.Scalar(rand.Reader, group)
	X := x.ActOnBase()
	sig := NewSignature(x, m, nil)

	eth := sig.SerializeEthereum()
	require.Len(t, eth, 65)

	// recovery id must be 0 or 1
	assert.Contains(t, []byte{0, 1}, eth[64])

	// the public key must be recoverable using the recovery id
	recovered := recoverEth(t, group, eth, eth[64], m)
	require.NotNil(t, recovered)
	assert.True(t, recovered.Equal(X), "public key must be recoverable from the ethereum signature")
}

func TestSignature_SerializeEthereum_HighS(t *testing.T) {
	group := curve.Secp256k1{}
	m := []byte("high s normalization")
	x := sample.Scalar(rand.Reader, group)
	X := x.ActOnBase()

	// try many k values until at least one signature has S > n/2
	lowSSeen, highSSeen := false, false
	for i := 0; i < 200 && !(lowSSeen && highSSeen); i++ {
		k := sample.Scalar(rand.Reader, group)
		sig := NewSignature(x, m, k)
		eth := sig.SerializeEthereum()
		require.Len(t, eth, 65)
		assert.Contains(t, []byte{0, 1}, eth[64])

		recovered := recoverEth(t, group, eth, eth[64], m)
		require.NotNil(t, recovered)
		assert.True(t, recovered.Equal(X), "recovery must succeed regardless of S parity")

		// determine whether the original S was high by checking if the
		// serialized s differs from the signature's S
		s := group.NewScalar()
		require.NoError(t, s.UnmarshalBinary(eth[32:64]))
		if s.Equal(sig.S) {
			lowSSeen = true
		} else {
			highSSeen = true
		}
	}
	assert.True(t, lowSSeen, "expected at least one low-S signature")
	assert.True(t, highSSeen, "expected at least one high-S signature (n/2 chance each)")
}

func TestSignature_SerializeEthereum_DoesNotMutate(t *testing.T) {
	group := curve.Secp256k1{}
	m := []byte("serialization must not mutate")
	x := sample.Scalar(rand.Reader, group)
	X := x.ActOnBase()

	for i := 0; i < 100; i++ {
		k := sample.Scalar(rand.Reader, group)
		sig := NewSignature(x, m, k)
		sBytes := sig.S.Bytes()
		require.True(t, sig.Verify(X, m))

		first := sig.SerializeEthereum()
		// the in-memory signature must be unchanged by serialization
		assert.Equal(t, sBytes, sig.S.Bytes(), "SerializeEthereum must not mutate S")
		assert.True(t, sig.Verify(X, m), "signature must still verify after SerializeEthereum")

		// serializing twice must be deterministic
		second := sig.SerializeEthereum()
		assert.Equal(t, first, second)
	}
}

// failingPoint and failingScalar implement the curve interfaces but fail
// marshalling, in order to exercise the panic paths of the serializers.
type failingPoint struct {
	curve.Point
}

func (failingPoint) MarshalBinary() ([]byte, error) {
	return nil, assert.AnError
}

type failingScalar struct {
	curve.Scalar
}

func (failingScalar) MarshalBinary() ([]byte, error) {
	return nil, assert.AnError
}

func TestSerialize_PanicOnMarshalFailure(t *testing.T) {
	group := curve.Secp256k1{}
	goodPoint := group.NewBasePoint()
	goodScalar := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1))

	assert.Panics(t, func() { _ = (&Signature{R: failingPoint{}, S: goodScalar}).Serialize() })
	assert.Panics(t, func() { _ = (&Signature{R: goodPoint, S: failingScalar{}}).Serialize() })
	assert.Panics(t, func() { _ = (&Signature{R: failingPoint{}, S: goodScalar}).SerializeEthereum() })
	assert.Panics(t, func() { _ = (&Signature{R: goodPoint, S: failingScalar{}}).SerializeEthereum() })
	assert.Panics(t, func() { _ = (&Signature{R: failingPoint{}, S: goodScalar}).SerializeDER() })
}

func TestSerializeDER_PanicOnTruncatedR(t *testing.T) {
	// the order is smaller than the field prime, so there exist valid curve
	// points with x >= n; serializing those must panic rather than truncate
	group := curve.Secp256k1{}
	pBig := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(0x1000003d1)) // 2^256 - 2^32 - 977 = p
	// find x in [n, p) that is on the curve
	x := pBig
	for i := 0; i < 64; i++ {
		R, err := group.LiftX(x.FillBytes(make([]byte, 32)))
		if err == nil {
			sig := &Signature{R: R, S: group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1))}
			assert.Panics(t, func() { sig.SerializeDER() })
			return
		}
		x = new(big.Int).Sub(x, big.NewInt(1))
	}
	t.Skip("no suitable x >= n found")
}

func TestSignature_SerializePrefixes(t *testing.T) {
	group := curve.Secp256k1{}
	m := []byte("prefix bytes")
	x := sample.Scalar(rand.Reader, group)
	sig := NewSignature(x, m, nil)

	// R must serialize with prefix 2 or 3
	data, err := sig.R.MarshalBinary()
	require.NoError(t, err)
	assert.Contains(t, []byte{2, 3}, data[0])

	// Serialize must place the point first and the scalar second
	full := sig.Serialize()
	assert.Equal(t, data, full[:33])
	sBytes, err := sig.S.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, sBytes, full[33:])
}
