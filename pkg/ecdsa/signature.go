package ecdsa

import (
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

type Signature struct {
	R curve.Point
	S curve.Scalar
}

// EmptySignature returns a new signature with a given curve, ready to be unmarshalled.
func EmptySignature(group curve.Curve) Signature {
	return Signature{R: group.NewPoint(), S: group.NewScalar()}
}

// Verify is a custom signature format using curve data.
func (sig Signature) Verify(X curve.Point, hash []byte) bool {
	group := X.Curve()

	r := sig.R.XScalar()

	if r.IsZero() || sig.S.IsZero() {
		return false
	}

	// TODO Do we also need to check for R or S > the group modulus?

	m := curve.FromHash(group, hash)
	sInv := group.NewScalar().Set(sig.S).Invert()
	mG := m.ActOnBase()
	rX := r.Act(X)
	R2 := mG.Add(rX)
	R2 = sInv.Act(R2)
	return R2.Equal(sig.R)
}

func (sig *Signature) SerializeDER() []byte {
	var r secp256k1.ModNScalar
	b, err := sig.R.MarshalBinary()
	trunc := r.SetByteSlice(b[1:])
	if err != nil || trunc {
		panic(sig)
	}
	var s secp256k1.ModNScalar
	b, err = sig.S.MarshalBinary()
	trunc = s.SetByteSlice(b)
	if err != nil || trunc {
		panic(sig)
	}
	return ecdsa.NewSignature(&r, &s).Serialize()
}
