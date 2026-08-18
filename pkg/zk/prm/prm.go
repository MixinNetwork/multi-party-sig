package zkprm

import (
	"crypto/rand"
	"io"
	"math/big"

	"github.com/MixinNetwork/multi-party-sig/common/params"
	"github.com/MixinNetwork/multi-party-sig/pkg/hash"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/arith"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/MixinNetwork/multi-party-sig/pkg/pedersen"
	"github.com/MixinNetwork/multi-party-sig/pkg/pool"
	"github.com/cronokirby/saferith"
)

type Public struct {
	Aux *pedersen.Parameters
}
type Private struct {
	Lambda, Phi, P, Q *saferith.Nat
}

type Proof struct {
	As, Zs [params.StatParam]*big.Int
}

func (p *Proof) IsValid(public Public) bool {
	if p == nil {
		return false
	}
	if !arith.IsValidBigModN(public.Aux.N().Big(), append(p.As[:], p.Zs[:]...)...) {
		return false
	}
	return true
}

// NewProof generates a proof that:
// s = t^lambda (mod N).
func NewProof(private Private, hash *hash.Hash, public Public, pl *pool.Pool) *Proof {
	lambda := private.Lambda
	phi := saferith.ModulusFromNat(private.Phi)

	n := arith.ModulusFromFactors(private.P, private.Q)

	var (
		as [params.StatParam]*saferith.Nat
		As [params.StatParam]*big.Int
	)
	lockedRand := pool.NewLockedReader(rand.Reader)
	pl.Parallelize(params.StatParam, func(i int) any {
		// aᵢ ∈ mod ϕ(N)
		as[i] = sample.ModN(lockedRand, phi)

		// Aᵢ = tᵃ mod N
		As[i] = n.Exp(public.Aux.T(), as[i]).Big()

		return nil
	})

	es, _ := challenge(hash, public, As)
	// Modular addition is not expensive enough to warrant parallelizing
	var Zs [params.StatParam]*big.Int
	for i := range params.StatParam {
		z := as[i]
		// The challenge is public, so branching is ok
		if es[i] {
			z.ModAdd(z, lambda, phi)
		}
		Zs[i] = z.Big()
	}

	return &Proof{
		As: As,
		Zs: Zs,
	}
}

func (p *Proof) Verify(public Public, hash *hash.Hash, pl *pool.Pool) bool {
	if p == nil {
		return false
	}
	if err := pedersen.ValidateParameters(public.Aux.N(), public.Aux.S(), public.Aux.T()); err != nil {
		return false
	}

	n, s, t := public.Aux.N().Big(), public.Aux.S().Big(), public.Aux.T().Big()

	es, err := challenge(hash, public, p.As)
	if err != nil {
		return false
	}

	one := big.NewInt(1)
	verifications := pl.Parallelize(params.StatParam, func(i int) any {
		var lhs, rhs big.Int
		z := p.Zs[i]
		a := p.As[i]

		if !arith.IsValidBigModN(n, a, z) {
			return false
		}

		if a.Cmp(one) == 0 {
			return false
		}

		lhs.Exp(t, z, n)
		if es[i] {
			rhs.Mul(a, s)
			rhs.Mod(&rhs, n)
		} else {
			rhs.Set(a)
		}

		if lhs.Cmp(&rhs) != 0 {
			return false
		}

		return true
	})
	for i := range verifications {
		ok, _ := verifications[i].(bool)
		if !ok {
			return false
		}
	}
	return true
}

func challenge(hash *hash.Hash, public Public, A [params.StatParam]*big.Int) (es []bool, err error) {
	if err = hash.WriteAny(public.Aux); err != nil {
		return nil, err
	}
	for _, a := range A {
		// A nil or otherwise unwritable element must fail loudly: silently
		// skipping it would corrupt the transcript.
		if err = hash.WriteAny(a); err != nil {
			return nil, err
		}
	}

	tmpBytes := make([]byte, params.StatParam)
	_, _ = io.ReadFull(hash.Digest(), tmpBytes)

	es = make([]bool, params.StatParam)
	for i := range es {
		b := (tmpBytes[i] & 1) == 1
		es[i] = b
	}

	return
}
