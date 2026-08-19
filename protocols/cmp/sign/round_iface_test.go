package sign

import (
	mrand "math/rand"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/internal/test"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/pkg/pool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func signSessions(t *testing.T, count int) ([]round.Session, party.IDSlice) {
	t.Helper()
	pl := pool.NewPool(1)
	t.Cleanup(pl.TearDown)
	group := curve.Secp256k1{}

	configs, partyIDs := test.GenerateConfig(group, count, count-1, mrand.New(mrand.NewSource(2304)), pl)
	partyIDs = partyIDs[:count]

	rounds := make([]round.Session, 0, count)
	for _, partyID := range partyIDs {
		r, err := StartSign(configs[partyID], partyIDs, []byte("message hash"), pl)(test.SessionID("sign-iface"))
		require.NoError(t, err)
		rounds = append(rounds, r)
	}
	return rounds, partyIDs
}

func advance(t *testing.T, rounds []round.Session, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err)
		require.False(t, done)
	}
}

func TestSignRoundInterfaceMethods(t *testing.T) {
	rounds, partyIDs := signSessions(t, 3)
	r1 := rounds[0]

	// round1 methods
	assert.Equal(t, round.Number(1), r1.Number())
	assert.Nil(t, r1.MessageContent())
	assert.NoError(t, r1.VerifyMessage(round.Message{}))
	assert.NoError(t, r1.StoreMessage(round.Message{}))

	// advance to round 5
	advance(t, rounds, 4)

	r5 := rounds[0].(*round5)
	assert.Equal(t, round.Number(5), r5.Number())
	assert.Nil(t, r5.MessageContent())
	assert.NoError(t, r5.VerifyMessage(round.Message{}))
	assert.NoError(t, r5.StoreMessage(round.Message{}))

	// wrong content type for the broadcast
	err := r5.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &broadcast2{}})
	assert.ErrorIs(t, err, round.ErrInvalidContent)

	// empty content must fail
	err = r5.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &broadcast5{}})
	assert.Error(t, err)
}

func TestSignStartErrors(t *testing.T) {
	pl := pool.NewPool(1)
	defer pl.TearDown()
	group := curve.Secp256k1{}

	configs, partyIDs := test.GenerateConfig(group, 3, 2, mrand.New(mrand.NewSource(99)), pl)

	// a valid signer set starts correctly
	_, err := StartSign(configs[partyIDs[0]], partyIDs, []byte("m"), pl)(test.SessionID("cfg"))
	require.NoError(t, err)

	// a signer set that is not a valid subset must fail
	unknown := []party.ID{"zz", "yy"}
	_, err = StartSign(configs[partyIDs[0]], unknown, []byte("m"), pl)(test.SessionID("unknown"))
	assert.Error(t, err)

	// a short session ID must fail
	_, err = StartSign(configs[partyIDs[0]], partyIDs, []byte("m"), pl)([]byte("short"))
	assert.Error(t, err)
}

func TestSignRound2Errors(t *testing.T) {
	rounds, partyIDs := signSessions(t, 3)
	advance(t, rounds, 1)

	r2 := rounds[0].(*round2)

	// wrong content type for the p2p message
	err := r2.VerifyMessage(round.Message{From: partyIDs[1], To: partyIDs[0], Content: &broadcast2{}})
	assert.ErrorIs(t, err, round.ErrInvalidContent)

	// empty message content must fail validation
	err = r2.VerifyMessage(round.Message{From: partyIDs[1], To: partyIDs[0], Content: &message2{}})
	assert.Error(t, err)
}

func TestSignRound3Errors(t *testing.T) {
	rounds, partyIDs := signSessions(t, 3)
	advance(t, rounds, 2)

	r3 := rounds[0].(*round3)

	// wrong content type
	err := r3.VerifyMessage(round.Message{From: partyIDs[1], To: partyIDs[0], Content: &broadcast3{}})
	assert.ErrorIs(t, err, round.ErrInvalidContent)

	// empty message content must fail
	err = r3.VerifyMessage(round.Message{From: partyIDs[1], To: partyIDs[0], Content: &message3{}})
	assert.Error(t, err)

	// wrong content type for the broadcast
	err = r3.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &message3{}})
	assert.ErrorIs(t, err, round.ErrInvalidContent)

	// an empty payload fails decryption cleanly instead of panicking
	err = r3.StoreMessage(round.Message{From: partyIDs[1], To: partyIDs[0], Content: &message3{}})
	assert.Error(t, err)
}

func TestSignRound4Errors(t *testing.T) {
	rounds, partyIDs := signSessions(t, 3)
	advance(t, rounds, 3)

	r4 := rounds[0].(*round4)

	// wrong content type for the p2p message
	err := r4.VerifyMessage(round.Message{From: partyIDs[1], To: partyIDs[0], Content: &broadcast4{}})
	assert.ErrorIs(t, err, round.ErrInvalidContent)

	// wrong content type for the broadcast
	err = r4.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &message4{}})
	assert.ErrorIs(t, err, round.ErrInvalidContent)

	// nil fields must be rejected cleanly (no panic)
	err = r4.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &broadcast4{}})
	assert.ErrorIs(t, err, round.ErrNilFields)

	// zero values must be rejected
	err = r4.StoreBroadcastMessage(round.Message{
		From: partyIDs[1],
		Content: &broadcast4{
			DeltaShare:    curve.Secp256k1{}.NewScalar(),
			BigDeltaShare: curve.Secp256k1{}.NewPoint(),
		},
	})
	assert.ErrorIs(t, err, round.ErrNilFields)
}
