package ecdsa

import (
	"crypto/rand"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/stretchr/testify/assert"
)

func NewSignature(x curve.Scalar, hash []byte, k curve.Scalar) *Signature {
	group := x.Curve()

	if k == nil {
		k = sample.Scalar(rand.Reader, group)
	}
	m := curve.FromHash(group, hash)
	kInv := group.NewScalar().Set(k).Invert()
	R := kInv.ActOnBase()
	r := R.XScalar()
	s := r.Mul(x).Add(m).Mul(k)
	return &Signature{
		R: R,
		S: s,
	}
}

func TestSignature_Verify(t *testing.T) {
	group := curve.Secp256k1{}

	m := []byte("hello")
	x := sample.Scalar(rand.Reader, group)
	X := x.ActOnBase()
	sig := NewSignature(x, m, nil)
	if !sig.Verify(X, m) {
		t.Error("verify failed")
	}
}

func TestSignature_Verify_Zero(t *testing.T) {
	group := curve.Secp256k1{}

	m := []byte("any message is valid")
	x := sample.Scalar(rand.Reader, group)
	X := x.ActOnBase()

	// s = 0
	s := group.NewScalar()
	assert.Equal(t, true, s.IsZero())
	R := s.ActOnBase()
	sig := &Signature{
		R: R,
		S: s,
	}
	if sig.Verify(X, m) {
		t.Error("zero R/S signature should not verify")
	}
}

// TODO Do we need a test for R or S > group modulus?

func TestSignature_Verify_IdentityPublicKey(t *testing.T) {
	group := curve.Secp256k1{}

	m := []byte("forgery attempt")
	// the identity point as public key
	X := group.NewPoint()
	assert.Equal(t, true, X.IsIdentity())

	// universal forgery under an identity public key: R = [t]G, s = t⁻¹⋅m
	tScalar := sample.Scalar(rand.Reader, group)
	mScalar := curve.FromHash(group, m)
	s := group.NewScalar().Set(tScalar).Invert().Mul(mScalar)
	R := tScalar.ActOnBase()
	sig := &Signature{
		R: R,
		S: s,
	}
	if sig.Verify(X, m) {
		t.Error("signature under identity public key should not verify")
	}
}
