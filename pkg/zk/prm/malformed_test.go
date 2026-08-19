package zkprm

import (
	"math/big"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/hash"
	"github.com/MixinNetwork/multi-party-sig/pkg/paillier"
	"github.com/MixinNetwork/multi-party-sig/pkg/pool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func prmSetup(t *testing.T) (*Proof, Public, *pool.Pool) {
	t.Helper()
	pl := pool.NewPool(0)
	t.Cleanup(pl.TearDown)

	sk := paillier.NewSecretKey(pl)
	ped, lambda := sk.GeneratePedersen()

	public := Public{
		Aux: ped,
	}

	proof := NewProof(Private{
		Lambda: lambda,
		Phi:    sk.Phi(),
		P:      sk.P(),
		Q:      sk.Q(),
	}, hash.New(), public, pl)
	require.True(t, proof.Verify(public, hash.New(), pl))
	return proof, public, pl
}

func TestPrm_Malformed(t *testing.T) {
	proof, public, pl := prmSetup(t)

	// a nil proof must not verify
	var nilProof *Proof
	assert.False(t, nilProof.Verify(public, hash.New(), pl))
	assert.False(t, nilProof.IsValid(public))

	// an empty proof fails IsValid (nil big.Ints)
	assert.False(t, (&Proof{}).IsValid(public))

	// tampering with a single A breaks the proof
	tampered := *proof
	tampered.As[0] = new(big.Int).Add(tampered.As[0], big.NewInt(2))
	assert.False(t, tampered.Verify(public, hash.New(), pl))

	// out-of-range values fail IsValid
	outOfRange := *proof
	outOfRange.Zs[0] = public.Aux.N().Big()
	assert.False(t, outOfRange.Verify(public, hash.New(), pl))

	// non-units fail IsValid (a multiple of a factor would be needed, so
	// use 0, which is never a unit)
	zero := *proof
	zero.As[0] = big.NewInt(0)
	assert.False(t, zero.IsValid(public))
}
