package pedersen

import (
	"fmt"
	"io"
	"math/big"

	"github.com/MixinNetwork/multi-party-sig/common/params"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/arith"
	"github.com/cronokirby/saferith"
)

type Error string

const (
	ErrNilFields    Error = "contains nil field"
	ErrSEqualT      Error = "S cannot be equal to T"
	ErrNotValidModN Error = "S and T must be in [1,…,N-1] and coprime to N"
	ErrNEven        Error = "N must be odd"
	ErrTrivial      Error = "S and T must not be ±1 (mod N)"
	ErrNotQR        Error = "S and T must have Jacobi symbol +1 (mod N)"
)

func (e Error) Error() string {
	return fmt.Sprintf("pedersen: %s", string(e))
}

type Parameters struct {
	n    *arith.Modulus
	s, t *saferith.Nat
}

// New returns a new set of Pedersen parameters.
// Assumes ValidateParameters(n, s, t) returns nil.
func New(n *arith.Modulus, s, t *saferith.Nat) *Parameters {
	return &Parameters{
		s: s,
		t: t,
		n: n,
	}
}

// ValidateParameters check n, s and t, and returns an error if any of the following is true:
// - n, s, or t is nil.
// - n is even.
// - s, t are not in [1, …,n-1].
// - s, t are not coprime to N.
// - s or t is ±1 (mod N) (these have order 1 or 2 and make commitments degenerate).
// - s or t has Jacobi symbol ≠ +1 (mod N) (s, t must be quadratic residues).
// - s = t.
func ValidateParameters(n *saferith.Modulus, s, t *saferith.Nat) error {
	if n == nil || s == nil || t == nil {
		return ErrNilFields
	}
	// s, t ∈ ℤₙˣ
	if !arith.IsValidNatModN(n, s, t) {
		return ErrNotValidModN
	}
	nBig := n.Big()
	// N must be odd (it is a Blum modulus); this is also required for big.Jacobi.
	if nBig.Bit(0) == 0 {
		return ErrNEven
	}
	// s, t ∉ {±1}: elements of order 1 or 2 make Pedersen commitments degenerate.
	one := big.NewInt(1)
	nMinusOne := new(big.Int).Sub(nBig, one)
	sBig, tBig := s.Big(), t.Big()
	if sBig.Cmp(one) == 0 || sBig.Cmp(nMinusOne) == 0 ||
		tBig.Cmp(one) == 0 || tBig.Cmp(nMinusOne) == 0 {
		return ErrTrivial
	}
	// s, t must be non-trivial quadratic residues: Jacobi symbol +1 rules out the
	// remaining small-order elements and non-residues. For a safe-prime modulus,
	// any unit ∉ {±1} with Jacobi symbol +1 has order divisible by a large prime.
	if big.Jacobi(sBig, nBig) != 1 || big.Jacobi(tBig, nBig) != 1 {
		return ErrNotQR
	}
	// s ≡ t
	// Compare private copies: saferith's comparison mutates its operands in
	// place, and these parameters are shared between concurrent protocol
	// sessions.
	if _, eq, _ := s.Clone().Cmp(t.Clone()); eq == 1 {
		return ErrSEqualT
	}
	return nil
}

// N = p•q, p ≡ q ≡ 3 mod 4.
func (p Parameters) N() *saferith.Modulus { return p.n.Modulus }

// N, but as an arith modulus, which is sometimes useful
func (p Parameters) NArith() *arith.Modulus { return p.n }

// S = r² mod N.
func (p Parameters) S() *saferith.Nat { return p.s }

// T = Sˡ mod N.
func (p Parameters) T() *saferith.Nat { return p.t }

// Commit computes sˣ tʸ (mod N)
//
// x and y are taken as saferith.Int, because we want to keep these values in secret,
// in general. The commitment produced, on the other hand, hides their values,
// and can be safely shared.
func (p Parameters) Commit(x, y *saferith.Int) *saferith.Nat {
	sx := p.n.ExpI(p.s, x)
	ty := p.n.ExpI(p.t, y)

	result := sx.ModMul(sx, ty, p.n.Modulus)

	return result
}

// Verify returns true if sᵃ tᵇ ≡ S Tᵉ (mod N).
func (p Parameters) Verify(a, b, e *saferith.Int, S, T *saferith.Nat) bool {
	if a == nil || b == nil || S == nil || T == nil || e == nil {
		return false
	}
	nMod := p.n.Modulus
	if !arith.IsValidNatModN(nMod, S, T) {
		return false
	}

	sa := p.n.ExpI(p.s, a)         // sᵃ (mod N)
	tb := p.n.ExpI(p.t, b)         // tᵇ (mod N)
	lhs := sa.ModMul(sa, tb, nMod) // lhs = sᵃ⋅tᵇ (mod N)

	te := p.n.ExpI(T, e)          // Tᵉ (mod N)
	rhs := te.ModMul(te, S, nMod) // rhs = S⋅Tᵉ (mod N)
	return lhs.Eq(rhs) == 1
}

// WriteTo implements io.WriterTo and should be used within the hash.Hash function.
func (p *Parameters) WriteTo(w io.Writer) (int64, error) {
	if p == nil {
		return 0, io.ErrUnexpectedEOF
	}
	nAll := int64(0)
	buf := make([]byte, params.BytesIntModN)

	// write N, S, T
	for _, i := range []*saferith.Nat{p.n.Nat(), p.s, p.t} {
		i.FillBytes(buf)
		n, err := w.Write(buf)
		nAll += int64(n)
		if err != nil {
			return nAll, err
		}
	}
	return nAll, nil
}

// Domain implements hash.WriterToWithDomain, and separates this type within hash.Hash.
func (Parameters) Domain() string {
	return "Pedersen Parameters"
}
