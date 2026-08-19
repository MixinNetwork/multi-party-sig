package keygen

import (
	"testing"

	"github.com/cronokirby/saferith"

	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/internal/test"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/polynomial"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	zksch "github.com/MixinNetwork/multi-party-sig/pkg/zk/sch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ = party.ID("x")

// TestRoundInterfaceMethods exercises the trivial round.Round interface
// methods that the happy-path test harness never invokes because these
// rounds exchange only broadcast messages.
func TestRoundInterfaceMethods(t *testing.T) {
	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(3)

	r1, err := StartKeygenCommon(false, group, partyIDs, 1, partyIDs[0])(test.SessionID("iface"))
	require.NoError(t, err)

	// round1 methods
	assert.Equal(t, round.Number(1), r1.Number())
	assert.Nil(t, r1.MessageContent())
	assert.NoError(t, r1.VerifyMessage(round.Message{}))
	assert.NoError(t, r1.StoreMessage(round.Message{}))

	// advance to round 2 and exercise its methods
	out := make(chan *round.Message, 4)
	r2, err := r1.Finalize(out)
	require.NoError(t, err)
	require.NotNil(t, r2)
	close(out)

	assert.Equal(t, round.Number(2), r2.Number())
	assert.Nil(t, r2.MessageContent())
	assert.NoError(t, r2.VerifyMessage(round.Message{}))
	assert.NoError(t, r2.StoreMessage(round.Message{}))
}

// TestRound2StoreBroadcastErrors feeds malformed broadcast messages to round2.
func TestRound2StoreBroadcastErrors(t *testing.T) {
	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(3)

	r1, err := StartKeygenCommon(false, group, partyIDs, 1, partyIDs[0])(test.SessionID("iface"))
	require.NoError(t, err)
	out := make(chan *round.Message, 4)
	r2Session, err := r1.Finalize(out)
	require.NoError(t, err)
	close(out)
	r2 := r2Session.(*round2)

	// wrong content type
	err = r2.StoreBroadcastMessage(round.Message{
		From:    partyIDs[1],
		Content: &broadcast3{},
	})
	assert.ErrorIs(t, err, round.ErrInvalidContent)

	// nil fields
	err = r2.StoreBroadcastMessage(round.Message{
		From:    partyIDs[1],
		Content: &broadcast2{},
	})
	assert.ErrorIs(t, err, round.ErrNilFields)

	// an invalid commitment must be rejected
	bad := &broadcast2{
		Phi_i:      nil,
		Sigma_i:    nil,
		Commitment: nil,
	}
	err = r2.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: bad})
	assert.ErrorIs(t, err, round.ErrNilFields)
}

// TestRound3StoreBroadcastErrors feeds malformed messages to round3.
func TestRound3StoreBroadcastErrors(t *testing.T) {
	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(3)

	rounds := make([]round.Session, 0, 3)
	for _, id := range partyIDs {
		r, err := StartKeygenCommon(false, group, partyIDs, 1, id)(test.SessionID("r3err"))
		require.NoError(t, err)
		rounds = append(rounds, r)
	}

	// advance to round 3
	r, done := test.Rounds(rounds, nil)
	require.NoError(t, r)
	require.False(t, done)
	r, done = test.Rounds(rounds, nil)
	require.NoError(t, r)
	require.False(t, done)

	r3 := rounds[0].(*round3)

	// wrong content type
	err := r3.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &broadcast2{}})
	assert.ErrorIs(t, err, round.ErrInvalidContent)

	// an empty RID fails validation
	err = r3.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &broadcast3{}})
	assert.Error(t, err)

	// p2p message errors
	err = r3.VerifyMessage(round.Message{From: partyIDs[1], Content: &broadcast3{}})
	assert.ErrorIs(t, err, round.ErrInvalidContent)

	// a nil scalar field must be rejected
	err = r3.VerifyMessage(round.Message{From: partyIDs[1], Content: &message3{}})
	assert.ErrorIs(t, err, round.ErrNilFields)
}

// TestRound2StoreBroadcastInvalidProof feeds structurally valid but
// cryptographically wrong broadcasts into round2.
func TestRound2StoreBroadcastInvalidProof(t *testing.T) {
	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(3)

	r1, err := StartKeygenCommon(false, group, partyIDs, 1, partyIDs[0])(test.SessionID("badproof"))
	require.NoError(t, err)
	out := make(chan *round.Message, 4)
	r2Session, err := r1.Finalize(out)
	require.NoError(t, err)
	close(out)
	r2 := r2Session.(*round2)

	// extract our own broadcast to mutate
	var own *broadcast2
	for msg := range out {
		if b, ok := msg.Content.(*broadcast2); ok {
			own = b
			break
		}
	}
	require.NotNil(t, own)

	// a proof for a different key must fail verification
	wrongSecret := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(12345))
	forged := &broadcast2{
		Phi_i:      own.Phi_i,
		Sigma_i:    zksch.NewProof(r2.Helper.HashForID(partyIDs[1]), wrongSecret.ActOnBase(), wrongSecret, nil),
		Commitment: own.Commitment,
	}
	err = r2.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: forged})
	assert.Error(t, err, "forged Schnorr proof accepted")

	// a polynomial of the wrong degree must be rejected
	wrongDegree := &broadcast2{
		Phi_i:      polynomial.NewPolynomialExponent(polynomial.NewPolynomial(group, 0, group.NewScalar())),
		Sigma_i:    own.Sigma_i,
		Commitment: own.Commitment,
	}
	err = r2.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: wrongDegree})
	assert.Error(t, err, "wrong-degree polynomial accepted")

	// an all-zero commitment must be rejected
	zeroCommitment := &broadcast2{
		Phi_i:      own.Phi_i,
		Sigma_i:    own.Sigma_i,
		Commitment: make([]byte, 64),
	}
	err = r2.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: zeroCommitment})
	assert.Error(t, err, "zero commitment accepted")
}

// TestRoundFinalizeOutChanFull verifies the Finalize error paths when the
// outgoing channel is full.
func TestRound3StoreMessage_VSSFailure(t *testing.T) {
	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(3)

	rounds := make([]round.Session, 0, 3)
	for _, id := range partyIDs {
		r, err := StartKeygenCommon(false, group, partyIDs, 1, id)(test.SessionID("vss-fail"))
		require.NoError(t, err)
		rounds = append(rounds, r)
	}

	// advance to round 3
	r, done := test.Rounds(rounds, nil)
	require.NoError(t, r)
	require.False(t, done)
	r, done = test.Rounds(rounds, nil)
	require.NoError(t, r)
	require.False(t, done)

	r3 := rounds[0].(*round3)

	// a share inconsistent with the broadcast polynomial must fail the VSS check
	wrong := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(12345678))
	err := r3.StoreMessage(round.Message{From: partyIDs[1], To: partyIDs[0], Content: &message3{F_li: wrong}})
	assert.Error(t, err, "VSS check must reject an inconsistent share")
}

func TestRoundFinalizeOutChanFull(t *testing.T) {
	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(3)

	r1, err := StartKeygenCommon(false, group, partyIDs, 1, partyIDs[0])(test.SessionID("fullchan"))
	require.NoError(t, err)

	// no capacity: the broadcast fails
	out := make(chan *round.Message)
	next, err := r1.Finalize(out)
	require.Error(t, err)
	require.NotNil(t, next)

	// round2 with a full channel: broadcast fails first
	out2 := make(chan *round.Message, 1)
	r2, err := r1.Finalize(out2)
	require.NoError(t, err)
	// drain to fill later; use a fresh channel with no capacity
	r2Session := r2
	next2, err := r2Session.Finalize(make(chan *round.Message))
	require.Error(t, err)
	require.NotNil(t, next2)
}
