package round_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/internal/test"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestHelper(t *testing.T) *round.Helper {
	t.Helper()
	partyIDs := test.PartyIDs(5)
	info := round.Info{
		ProtocolID:       "TEST",
		FinalRoundNumber: 3,
		SelfID:           partyIDs[0],
		PartyIDs:         partyIDs,
		Threshold:        2,
		Group:            curve.Secp256k1{},
	}
	helper, err := round.NewSession(info, test.SessionID("helper"), nil)
	require.NoError(t, err)
	return helper
}

func TestHelper_Accessors(t *testing.T) {
	helper := newTestHelper(t)
	partyIDs := helper.PartyIDs()

	assert.Equal(t, "TEST", helper.ProtocolID())
	assert.Equal(t, round.Number(3), helper.FinalRoundNumber())
	assert.Equal(t, partyIDs[0], helper.SelfID())
	assert.Equal(t, 2, helper.Threshold())
	assert.Equal(t, 5, helper.N())
	assert.Equal(t, "secp256k1", helper.Group().Name())
	require.Len(t, partyIDs, 5)
	assert.Equal(t, partyIDs.Remove(partyIDs[0]), helper.OtherPartyIDs())
	assert.NotContains(t, helper.OtherPartyIDs(), helper.SelfID())
	assert.NotEmpty(t, helper.SSID())

	// the SSID must be deterministic for the same session parameters
	helper2 := newTestHelper(t)
	assert.Equal(t, helper.SSID(), helper2.SSID())
}

func TestHelper_SessionIDChangesSSID(t *testing.T) {
	partyIDs := test.PartyIDs(5)
	info := round.Info{
		ProtocolID:       "TEST",
		FinalRoundNumber: 3,
		SelfID:           partyIDs[0],
		PartyIDs:         partyIDs,
		Threshold:        2,
		Group:            curve.Secp256k1{},
	}
	h1, err := round.NewSession(info, test.SessionID("one"), nil)
	require.NoError(t, err)
	h2, err := round.NewSession(info, test.SessionID("two"), nil)
	require.NoError(t, err)
	assert.NotEqual(t, h1.SSID(), h2.SSID())
}

func TestHelper_HashAndForks(t *testing.T) {
	helper := newTestHelper(t)

	h1 := helper.Hash()
	h2 := helper.Hash()
	// clones must produce the same digest
	assert.Equal(t, h1.Sum(), h2.Sum())

	// HashForID must fork per party
	ha := helper.HashForID(party.ID("a"))
	hb := helper.HashForID(party.ID("b"))
	assert.NotEqual(t, ha.Sum(), hb.Sum())

	// an empty ID returns the unmodified state
	hEmpty := helper.HashForID("")
	assert.Equal(t, helper.Hash().Sum(), hEmpty.Sum())

	// UpdateHashState advances the shared state
	before := helper.Hash().Sum()
	helper.UpdateHashState(testMessage("extra"))
	after := helper.Hash().Sum()
	assert.NotEqual(t, before, after)
}

type testMessage []byte

func (m testMessage) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(m)
	return int64(n), err
}

func (testMessage) Domain() string { return "testMessage" }

func TestHelper_Messages(t *testing.T) {
	helper := newTestHelper(t)

	out := make(chan *round.Message, 10)
	require.NoError(t, helper.BroadcastMessage(out, nil))
	require.NoError(t, helper.SendMessage(out, nil, "other"))

	msgBroadcast := <-out
	assert.True(t, msgBroadcast.Broadcast)
	assert.Equal(t, helper.SelfID(), msgBroadcast.From)
	assert.Equal(t, party.ID(""), msgBroadcast.To)

	msgP2P := <-out
	assert.False(t, msgP2P.Broadcast)
	assert.Equal(t, helper.SelfID(), msgP2P.From)
	assert.Equal(t, party.ID("other"), msgP2P.To)

	// a full channel must produce ErrOutChanFull
	full := make(chan *round.Message)
	assert.ErrorIs(t, helper.BroadcastMessage(full, nil), round.ErrOutChanFull)
	assert.ErrorIs(t, helper.SendMessage(full, nil, "other"), round.ErrOutChanFull)
}

func TestHelper_ResultAndAbortRounds(t *testing.T) {
	helper := newTestHelper(t)

	result := struct{}{}
	output := helper.ResultRound(result)
	require.IsType(t, &round.Output{}, output)
	outRound := output.(*round.Output)
	assert.Equal(t, result, outRound.Result)
	assert.Equal(t, round.Number(0), output.Number())

	// Finalize on the output round returns itself
	next, err := output.Finalize(nil)
	require.NoError(t, err)
	assert.Equal(t, output, next)
	assert.NoError(t, output.VerifyMessage(round.Message{}))
	assert.NoError(t, output.StoreMessage(round.Message{}))
	assert.Nil(t, output.MessageContent())

	culprit := helper.PartyIDs()[1]
	abortErr := errors.New("some failure")
	abort := helper.AbortRound(abortErr, culprit)
	require.IsType(t, &round.Abort{}, abort)
	abortRound := abort.(*round.Abort)
	assert.Equal(t, abortErr, abortRound.Err)
	assert.Equal(t, []party.ID{culprit}, abortRound.Culprits)
	assert.Equal(t, round.Number(0), abort.Number())

	next, err = abort.Finalize(nil)
	require.NoError(t, err)
	assert.Equal(t, abort, next)
	assert.NoError(t, abort.VerifyMessage(round.Message{}))
	assert.NoError(t, abort.StoreMessage(round.Message{}))
	assert.Nil(t, abort.MessageContent())
}

func TestBroadcastContent_Reliable(t *testing.T) {
	assert.True(t, round.ReliableBroadcastContent{}.Reliable())
	assert.False(t, round.NormalBroadcastContent{}.Reliable())
}

func TestNumber_WriteTo(t *testing.T) {
	var buf bytes.Buffer
	n, err := round.Number(0x0102).WriteTo(&buf)
	require.NoError(t, err)
	// a uint64 (8 bytes) is written
	assert.Equal(t, int64(8), n)
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 1, 2}, buf.Bytes())
	assert.Equal(t, "Round Number", round.Number(0).Domain())
}

func TestNewSession_TooManyPartiesForThreshold(t *testing.T) {
	// n <= 0 cannot happen via partyIDs directly, but an empty list can
	info := round.Info{
		ProtocolID:       "TEST",
		FinalRoundNumber: 1,
		SelfID:           "a",
		PartyIDs:         []party.ID{"a"},
		Threshold:        0,
		Group:            curve.Secp256k1{},
	}
	_, err := round.NewSession(info, test.SessionID("single"), nil)
	require.NoError(t, err)

	// a nil group must fail
	info.Group = nil
	_, err = round.NewSession(info, test.SessionID("nilgroup"), nil)
	assert.Error(t, err)
}

func TestNewSession_AuxInfo(t *testing.T) {
	partyIDs := test.PartyIDs(3)
	info := round.Info{
		ProtocolID:       "TEST",
		FinalRoundNumber: 1,
		SelfID:           partyIDs[0],
		PartyIDs:         partyIDs,
		Threshold:        1,
		Group:            curve.Secp256k1{},
	}
	h1, err := round.NewSession(info, test.SessionID("aux"), nil, testMessage("hello"))
	require.NoError(t, err)
	h2, err := round.NewSession(info, test.SessionID("aux"), nil, testMessage("world"))
	require.NoError(t, err)
	h3, err := round.NewSession(info, test.SessionID("aux"), nil)
	require.NoError(t, err)
	// aux info affects the SSID
	assert.NotEqual(t, h1.SSID(), h2.SSID())
	assert.NotEqual(t, h1.SSID(), h3.SSID())

	// a nil entry is skipped without error
	_, err = round.NewSession(info, test.SessionID("aux"), nil, nil, testMessage("x"))
	require.NoError(t, err)
}
