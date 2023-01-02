package ecdsa

import (
	"fmt"

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

func ParseSignature(group curve.Curve, b []byte) (*Signature, error) {
	if len(b) != 65 {
		return nil, fmt.Errorf("UnmarshalSignature(%x) %d", b, len(b))
	}

	sig := EmptySignature(group)
	err := sig.R.UnmarshalBinary(b[:33])
	if err != nil {
		return nil, err
	}
	err = sig.S.UnmarshalBinary(b[33:])
	if err != nil {
		return nil, err
	}

	return &sig, nil
}

func (sig *Signature) Serialize() []byte {
	r, err := sig.R.MarshalBinary()
	if err != nil {
		panic(sig)
	}
	s, err := sig.S.MarshalBinary()
	if err != nil {
		panic(sig)
	}
	return append(r, s...)
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

func (sig *Signature) SerializeEthereum() []byte {
	rb, err := sig.R.MarshalBinary()
	if err != nil {
		panic(sig)
	}
	rb[0] = rb[0] - 2

	sb, err := sig.S.MarshalBinary()
	if err != nil {
		panic(sig)
	}

	var ss secp256k1.ModNScalar
	ss.SetByteSlice(sb)
	if ss.IsOverHalfOrder() {
		sb, err = sig.S.Negate().MarshalBinary()
		if err != nil {
			panic(err)
		}
		rb[0] ^= 0x01
	}

	out := append(rb[1:], sb...)
	return append(out, rb[0])
}
