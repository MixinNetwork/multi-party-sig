package arith

import (
	"math/big"

	"github.com/MixinNetwork/multi-party-sig/common/params"
	"github.com/cronokirby/saferith"
)

// maxAnnouncedSlack is the margin, in bits, above the modulus' bit length that
// the announced length of a valid Nat is allowed to have. Honest encodings of
// a reduced value mod N carry exactly N's bit length; anything larger is
// zero-padding, whose announced length drives the cost of the constant-time
// operations below (CmpMod, IsUnit) and of any later modular arithmetic —
// an attacker-controlled announced length is a CPU-amplification DoS.
const maxAnnouncedSlack = 64

// IsValidNatModN checks that ints are all in the range [1,…,N-1] and co-prime to N.
//
// Neither N nor the values are mutated.
func IsValidNatModN(N *saferith.Modulus, ints ...*saferith.Nat) bool {
	for _, i := range ints {
		if i == nil {
			return false
		}
		// A reduced value mod N fits in N's bit length; reject padded
		// encodings before they reach the expensive operations below.
		if i.AnnouncedLen() > N.BitLen()+maxAnnouncedSlack {
			return false
		}
		if !IsBelowModN(i, N) {
			return false
		}
		if i.IsUnit(N) != 1 {
			return false
		}
	}
	return true
}

// IsBelowModN returns true if the value of i is strictly less than N.
//
// It is a side-effect-free replacement for i.CmpMod(N): saferith's
// comparisons resize and mask the limb slices of both operands in place, so
// concurrent comparisons against a shared *saferith.Modulus — for example the
// ones cached inside a paillier.PublicKey or pedersen.Parameters held by
// concurrent protocol sessions — are a data race, even though the mutation
// preserves the value. This function compares private copies instead.
func IsBelowModN(i *saferith.Nat, N *saferith.Modulus) bool {
	in := new(saferith.Nat).SetNat(i)
	mod := N.Nat()
	_, _, lt := in.Cmp(mod)
	return lt == 1
}

// IsValidBigModN checks that ints are all in the range [1,…,N-1] and co-prime to N.
func IsValidBigModN(N *big.Int, ints ...*big.Int) bool {
	var gcd big.Int
	one := big.NewInt(1)
	for _, i := range ints {
		if i == nil {
			return false
		}
		if i.Sign() != 1 {
			return false
		}
		if i.Cmp(N) != -1 {
			return false
		}
		gcd.GCD(nil, nil, i, N)
		if gcd.Cmp(one) != 0 {
			return false
		}
	}
	return true
}

// IsInIntervalLEps returns true if n ∈ [-2ˡ⁺ᵉ,…,2ˡ⁺ᵉ].
func IsInIntervalLEps(n *saferith.Int) bool {
	if n == nil {
		return false
	}
	return n.TrueLen() <= params.LPlusEpsilon
}

// IsInIntervalLPrimeEps returns true if n ∈ [-2ˡ'⁺ᵉ,…,2ˡ'⁺ᵉ].
func IsInIntervalLPrimeEps(n *saferith.Int) bool {
	if n == nil {
		return false
	}
	return n.TrueLen() <= params.LPrimePlusEpsilon
}

// IsInIntervalLEpsPlus1RootN returns true if n ∈ [-2¹⁺ˡ⁺ᵉ√N,…,2¹⁺ˡ⁺ᵉ√N], for a Paillier modulus N.
func IsInIntervalLEpsPlus1RootN(n *saferith.Int) bool {
	if n == nil {
		return false
	}
	return n.TrueLen() <= 1+params.LPlusEpsilon+(params.BitsIntModN/2)
}

// MaxIntResponseBits bounds the announced size of any *saferith.Int field
// appearing in a zero-knowledge proof. The cost of saferith modular operations
// scales with the announced size of their inputs, and an Int decoded from the
// wire takes its announced size directly from the attacker's data (8 × length).
// Legitimate proof responses are always well below this bound — the largest is
// Πfac's v at ~4865 bits — so anything bigger is rejected before any expensive
// exponentiation is performed.
const MaxIntResponseBits = 5120

// IsValidIntLen returns true if n is non-nil and its announced size is at most
// MaxIntResponseBits bits. Note that checking TrueLen would NOT be sufficient:
// a large zero-filled input has a small true length but still forces expensive
// constant-time arithmetic.
func IsValidIntLen(n *saferith.Int) bool {
	if n == nil {
		return false
	}
	return n.AnnouncedLen() <= MaxIntResponseBits
}
