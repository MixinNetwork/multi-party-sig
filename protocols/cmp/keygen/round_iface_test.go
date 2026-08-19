package keygen

import (
	"testing"

	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/internal/test"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/pool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cmpKeygenRounds(t *testing.T) (round.Session, round.Session) {
	t.Helper()
	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(3)
	info := round.Info{
		ProtocolID:       "cmp/keygen-threshold",
		FinalRoundNumber: Rounds,
		SelfID:           partyIDs[0],
		PartyIDs:         partyIDs,
		Threshold:        1,
		Group:            group,
	}
	r1, err := Start(info, nil)(test.SessionID("iface"))
	require.NoError(t, err)

	out := make(chan *round.Message, 4)
	r2, err := r1.Finalize(out)
	require.NoError(t, err)
	close(out)
	return r1, r2
}

func TestRoundInterfaceMethods(t *testing.T) {
	r1, r2 := cmpKeygenRounds(t)

	// round1 methods
	assert.Equal(t, round.Number(1), r1.Number())
	assert.Nil(t, r1.MessageContent())
	assert.Nil(t, r1.(*round1).PreviousRound())
	assert.NoError(t, r1.VerifyMessage(round.Message{}))
	assert.NoError(t, r1.StoreMessage(round.Message{}))

	// round2 methods
	assert.Equal(t, round.Number(2), r2.Number())
	assert.Nil(t, r2.MessageContent())
	assert.NotNil(t, r2.(*round2).PreviousRound())
	assert.NoError(t, r2.VerifyMessage(round.Message{}))
	assert.NoError(t, r2.StoreMessage(round.Message{}))
}

func TestRound45InterfaceMethods(t *testing.T) {
	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(3)

	rounds := make([]round.Session, 0, 3)
	for _, id := range partyIDs {
		info := round.Info{
			ProtocolID:       "cmp/keygen-threshold",
			FinalRoundNumber: Rounds,
			SelfID:           id,
			PartyIDs:         partyIDs,
			Threshold:        1,
			Group:            group,
		}
		r, err := Start(info, nil)(test.SessionID("r45"))
		require.NoError(t, err)
		rounds = append(rounds, r)
	}

	// advance to round 5
	for i := 0; i < 4; i++ {
		r, done := test.Rounds(rounds, nil)
		require.NoError(t, r)
		require.False(t, done)
	}

	r5 := rounds[0].(*round5)
	assert.Equal(t, round.Number(5), r5.Number())
	assert.NoError(t, r5.VerifyMessage(round.Message{}))
	assert.NoError(t, r5.StoreMessage(round.Message{}))

	// wrong content type for the round5 broadcast
	err := r5.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &broadcast2{}})
	assert.ErrorIs(t, err, round.ErrInvalidContent)

	// nil fields must be rejected
	err = r5.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &broadcast5{}})
	assert.ErrorIs(t, err, round.ErrNilFields)
}

func TestRound4MessageErrors(t *testing.T) {
	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(3)

	rounds := make([]round.Session, 0, 3)
	for _, id := range partyIDs {
		info := round.Info{
			ProtocolID:       "cmp/keygen-threshold",
			FinalRoundNumber: Rounds,
			SelfID:           id,
			PartyIDs:         partyIDs,
			Threshold:        1,
			Group:            group,
		}
		r, err := Start(info, nil)(test.SessionID("r4err"))
		require.NoError(t, err)
		rounds = append(rounds, r)
	}

	// advance to round 4
	for i := 0; i < 3; i++ {
		r, done := test.Rounds(rounds, nil)
		require.NoError(t, r)
		require.False(t, done)
	}

	r4 := rounds[0].(*round4)

	// wrong content type
	err := r4.VerifyMessage(round.Message{From: partyIDs[1], To: partyIDs[0], Content: &broadcast2{}})
	assert.ErrorIs(t, err, round.ErrInvalidContent)

	// a nil share fails ciphertext validation
	err = r4.VerifyMessage(round.Message{From: partyIDs[1], To: partyIDs[0], Content: &message4{}})
	assert.Error(t, err)

	// round3's message content accessor
	assert.NotNil(t, rounds[0])
}

func TestRound3MessageContent(t *testing.T) {
	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(3)

	rounds := make([]round.Session, 0, 3)
	for _, id := range partyIDs {
		info := round.Info{
			ProtocolID:       "cmp/keygen-threshold",
			FinalRoundNumber: Rounds,
			SelfID:           id,
			PartyIDs:         partyIDs,
			Threshold:        1,
			Group:            group,
		}
		r, err := Start(info, nil)(test.SessionID("r3mc"))
		require.NoError(t, err)
		rounds = append(rounds, r)
	}

	r, done := test.Rounds(rounds, nil)
	require.NoError(t, r)
	require.False(t, done)
	r, done = test.Rounds(rounds, nil)
	require.NoError(t, r)
	require.False(t, done)

	r3 := rounds[0].(*round3)
	assert.Nil(t, r3.MessageContent(), "round3 has no p2p message content")

	// nil fields must be rejected
	err := r3.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &broadcast3{}})
	assert.ErrorIs(t, err, round.ErrNilFields)

	// an identity ElGamal key must be rejected
	err = r3.StoreBroadcastMessage(round.Message{
		From: partyIDs[1],
		Content: &broadcast3{
			ElGamalPublic: group.NewPoint(),
		},
	})
	assert.ErrorIs(t, err, round.ErrNilFields)
}

func TestRound2Finalize_OutChanFull(t *testing.T) {
	_, r2 := cmpKeygenRounds(t)

	// an unbuffered channel makes the broadcast fail
	next, err := r2.Finalize(make(chan *round.Message))
	require.Error(t, err)
	require.NotNil(t, next)
}

func TestRound3Finalize_OutChanFull(t *testing.T) {
	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(3)

	rounds := make([]round.Session, 0, 3)
	for _, id := range partyIDs {
		info := round.Info{
			ProtocolID:       "cmp/keygen-threshold",
			FinalRoundNumber: Rounds,
			SelfID:           id,
			PartyIDs:         partyIDs,
			Threshold:        1,
			Group:            group,
		}
		r, err := Start(info, nil)(test.SessionID("r3full"))
		require.NoError(t, err)
		rounds = append(rounds, r)
	}

	r, done := test.Rounds(rounds, nil)
	require.NoError(t, r)
	require.False(t, done)
	r, done = test.Rounds(rounds, nil)
	require.NoError(t, r)
	require.False(t, done)

	// an unbuffered channel fails the broadcast in round 3's Finalize
	next, err := rounds[0].Finalize(make(chan *round.Message))
	require.Error(t, err)
	require.NotNil(t, next)
}

func TestStart_InvalidSession(t *testing.T) {
	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(3)
	info := round.Info{
		ProtocolID:       "cmp/keygen-threshold",
		FinalRoundNumber: Rounds,
		SelfID:           "zz", // not in the party list
		PartyIDs:         partyIDs,
		Threshold:        1,
		Group:            group,
	}
	_, err := Start(info, nil)(test.SessionID("bad"))
	assert.Error(t, err)
}

func TestRound2StoreBroadcastErrors(t *testing.T) {
	_, r2 := cmpKeygenRounds(t)
	partyIDs := test.PartyIDs(3)

	// wrong content type
	err := r2.(*round2).StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &broadcast3{}})
	assert.ErrorIs(t, err, round.ErrInvalidContent)

	// nil commitment fails validation
	err = r2.(*round2).StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &broadcast2{}})
	assert.Error(t, err)
}

func TestRound3InterfaceMethods(t *testing.T) {
	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(3)

	pl := pool.NewPool(1)
	defer pl.TearDown()

	rounds := make([]round.Session, 0, 3)
	for _, id := range partyIDs {
		info := round.Info{
			ProtocolID:       "cmp/keygen-threshold",
			FinalRoundNumber: Rounds,
			SelfID:           id,
			PartyIDs:         partyIDs,
			Threshold:        1,
			Group:            group,
		}
		r, err := Start(info, pl)(test.SessionID("r3"))
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
	assert.Equal(t, round.Number(3), r3.Number())
	assert.NoError(t, r3.VerifyMessage(round.Message{}))
	assert.NoError(t, r3.StoreMessage(round.Message{}))

	// wrong content type for the broadcast
	err := r3.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &broadcast2{}})
	assert.ErrorIs(t, err, round.ErrInvalidContent)

	// empty broadcast content must fail
	err = r3.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &broadcast3{}})
	assert.Error(t, err)
}
