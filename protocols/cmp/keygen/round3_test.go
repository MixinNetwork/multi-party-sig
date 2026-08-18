package keygen

import (
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/polynomial"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	zksch "github.com/MixinNetwork/multi-party-sig/pkg/zk/sch"
)

// A round-3 broadcast carrying the identity ElGamal key must be rejected: the
// identity's encoding cannot be unmarshalled back, so accepting it would
// poison the persisted config of every honest party (glm-audit #7 /
// second-audit NEW-4). The identity can show up through a sparse (e.g. CBOR)
// decoding that omits the field, leaving the pre-seeded identity point behind.
func TestRound3RejectsIdentityElGamal(t *testing.T) {
	validBody := func() *broadcast3 {
		return &broadcast3{
			N:                  saferith.ModulusFromNat(new(saferith.Nat).SetUint64(21)),
			S:                  new(saferith.Nat).SetUint64(4),
			T:                  new(saferith.Nat).SetUint64(2),
			VSSPolynomial:      polynomial.EmptyExponent(group),
			SchnorrCommitments: zksch.EmptyCommitment(group),
			ElGamalPublic:      group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1)).ActOnBase(),
		}
	}
	r := &round3{}

	// identity ElGamal (what a sparse decoding leaves behind)
	body := validBody()
	body.ElGamalPublic = group.NewPoint()
	err := r.StoreBroadcastMessage(round.Message{From: party.ID("b"), Content: body})
	assert.ErrorIs(t, err, round.ErrNilFields)

	// nil ElGamal
	body = validBody()
	body.ElGamalPublic = nil
	err = r.StoreBroadcastMessage(round.Message{From: party.ID("b"), Content: body})
	assert.ErrorIs(t, err, round.ErrNilFields)

	// control: a valid ElGamal key gets past this check (and fails later, on
	// the RID length, with a different error)
	err = r.StoreBroadcastMessage(round.Message{From: party.ID("b"), Content: validBody()})
	require.Error(t, err)
	assert.NotErrorIs(t, err, round.ErrNilFields)
}
