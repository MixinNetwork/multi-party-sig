package paillier

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/cronokirby/saferith"
	"github.com/MixinNetwork/multi-party-sig/common/params"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/arith"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
)

var (
	ErrPaillierLength = errors.New("wrong number bit length of Paillier modulus N")
	ErrPaillierEven   = errors.New("modulus N is even")
	ErrPaillierNil    = errors.New("modulus N is nil")
)

// PublicKey is a Paillier public key. It is represented by a modulus N.
type PublicKey struct {
	// n = p⋅q
	n *arith.Modulus
	// nSquared = n²
	nSquared *arith.Modulus

	// These values are cached out of convenience, and performance
	nNat *saferith.Nat
	// nPlusOne = n + 1
	nPlusOne *saferith.Nat
}

// N is the public modulus making up this key.
func (pk *PublicKey) N() *saferith.Modulus {
	return pk.n.Modulus
}

// NewPublicKey returns an initialized paillier.PublicKey and caches N, N² and (N-1)/2.
func NewPublicKey(n *saferith.Modulus) *PublicKey {
	oneNat := new(saferith.Nat).SetUint64(1)
	nNat := n.Nat()
	nSquared := saferith.ModulusFromNat(new(saferith.Nat).Mul(nNat, nNat, -1))
	nPlusOne := new(saferith.Nat).Add(nNat, oneNat, -1)
	// Tightening is fine, since n is public
	nPlusOne.Resize(nPlusOne.TrueLen())

	return &PublicKey{
		n:        arith.ModulusFromN(n),
		nSquared: arith.ModulusFromN(nSquared),
		nNat:     nNat,
		nPlusOne: nPlusOne,
	}
}

// ValidateN performs basic checks to make sure the modulus is valid:
// - log₂(n) = params.BitsPaillier.
// - n is odd.
//
// Note: saferith.Modulus always normalizes its announced length to its true
// bit length on construction (see ModulusFromNat / UnmarshalBinary), so a
// zero-padded modulus encoding cannot be used to inflate the cost of the
// constant-time arithmetic performed with this key.
func ValidateN(n *saferith.Modulus) error {
	if n == nil {
		return ErrPaillierNil
	}
	// log₂(N) = BitsPaillier
	nBig := n.Big()
	if bits := nBig.BitLen(); bits != params.BitsPaillier {
		return fmt.Errorf("have: %d, need %d: %w", bits, params.BitsPaillier, ErrPaillierLength)
	}
	if nBig.Bit(0) != 1 {
		return ErrPaillierEven
	}
	return nil
}

// Enc returns the encryption of m under the public key pk.
// The nonce used to encrypt is returned.
//
// The message m must be in the range [-(N-1)/2, …, (N-1)/2] and panics otherwise.
//
// ct = (1+N)ᵐρᴺ (mod N²).
func (pk PublicKey) Enc(m *saferith.Int) (*Ciphertext, *saferith.Nat) {
	nonce := sample.UnitModN(rand.Reader, pk.n.Modulus)
	return pk.EncWithNonce(m, nonce), nonce
}

// EncWithNonce returns the encryption of m under the public key pk.
// The nonce is not returned.
//
// The message m must be in the range [-(N-1)/2, …, (N-1)/2] and panics otherwise
//
// ct = (1+N)ᵐρᴺ (mod N²).
func (pk PublicKey) EncWithNonce(m *saferith.Int, nonce *saferith.Nat) *Ciphertext {
	mAbs := m.Abs()
	nHalf := new(saferith.Nat).SetNat(pk.nNat)
	nHalf.Rsh(nHalf, 1, -1)
	if gt, _, _ := mAbs.Cmp(nHalf); gt == 1 {
		panic("paillier.Encrypt: tried to encrypt message outside of range [-(N-1)/2, …, (N-1)/2]")
	}

	// (N+1)ᵐ mod N²
	c := pk.nSquared.ExpI(pk.nPlusOne, m)
	// ρᴺ mod N²
	rhoN := pk.nSquared.Exp(nonce, pk.nNat)
	// (N+1)ᵐ rho ^ N
	c.ModMul(c, rhoN, pk.nSquared.Modulus)

	return &Ciphertext{c: c}
}

// Equal returns true if pk ≡ other.
//
// The comparison uses private copies: saferith's comparisons mutate their
// operands in place, and keys shared between concurrent protocol sessions
// must stay read-only.
func (pk PublicKey) Equal(other *PublicKey) bool {
	thisN, otherN := pk.n.Modulus.Nat(), other.n.Modulus.Nat()
	_, eq, _ := thisN.Cmp(otherN)
	return eq == 1
}

// ValidateCiphertexts checks if all ciphertexts are in the correct range and coprime to N²
// ct ∈ [1, …, N²-1] AND GCD(ct,N²) = 1.
func (pk PublicKey) ValidateCiphertexts(cts ...*Ciphertext) bool {
	for _, ct := range cts {
		if ct == nil {
			return false
		}
		// Belt-and-suspenders against padded encodings: the announced length
		// drives the cost of the checks below. The decode path already caps
		// this (see UnmarshalBinary); keep the check for constructions that
		// bypass it.
		if ct.c.AnnouncedLen() > 2*params.BitsPaillier+64 {
			return false
		}
		// IsBelowModN, unlike ct.c.CmpMod, does not mutate the shared modulus
		// cached in this key.
		if !arith.IsBelowModN(ct.c, pk.nSquared.Modulus) {
			return false
		}
		if ct.c.IsUnit(pk.nSquared.Modulus) != 1 {
			return false
		}
	}
	return true
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (pk *PublicKey) WriteTo(w io.Writer) (int64, error) {
	if pk == nil {
		return 0, io.ErrUnexpectedEOF
	}
	buf := pk.n.Bytes()
	n, err := w.Write(buf)
	return int64(n), err
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (PublicKey) Domain() string {
	return "Paillier PublicKey"
}

// Modulus returns an arith.Modulus for N which may allow for accelerated exponentiation when this
// public key was generated from a secret key.
func (pk *PublicKey) Modulus() *arith.Modulus {
	return pk.n
}

// ModulusSquared returns an arith.Modulus for N² which may allow for accelerated exponentiation when this
// public key was generated from a secret key.
func (pk *PublicKey) ModulusSquared() *arith.Modulus {
	return pk.nSquared
}
