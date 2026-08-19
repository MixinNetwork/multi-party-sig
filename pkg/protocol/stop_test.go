package protocol_test

import (
	"testing"
	"time"

	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/pkg/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recvOrTimeout reads from a handler's channel, failing the test instead of
// hanging if nothing arrives.
func recvOrTimeout(t *testing.T, ch <-chan *protocol.Message) (*protocol.Message, bool) {
	t.Helper()
	select {
	case m, ok := <-ch:
		return m, ok
	case <-time.After(30 * time.Second):
		t.Fatal("no message or close within 30s (is Stop a no-op?)")
		return nil, false
	}
}

// dummyContent is a broadcast payload for the minimal protocol below.
type dummyContent struct {
	round.NormalBroadcastContent
	Foo int
}

func (dummyContent) RoundNumber() round.Number { return 2 }

// dummyRound1 immediately broadcasts and waits in round 2 for the other
// party, so a handler sitting in this protocol is provably "running".
type dummyRound1 struct {
	*round.Helper
}

func (r *dummyRound1) VerifyMessage(round.Message) error { return nil }
func (r *dummyRound1) StoreMessage(round.Message) error  { return nil }
func (r *dummyRound1) Finalize(out chan<- *round.Message) (round.Session, error) {
	if err := r.BroadcastMessage(out, &dummyContent{Foo: 1}); err != nil {
		return r, err
	}
	return &dummyRound2{dummyRound1: r}, nil
}
func (r *dummyRound1) MessageContent() round.Content { return nil }
func (r *dummyRound1) Number() round.Number         { return 1 }

type dummyRound2 struct {
	*dummyRound1
}

func (r *dummyRound2) VerifyMessage(round.Message) error { return nil }
func (r *dummyRound2) StoreMessage(round.Message) error  { return nil }
func (r *dummyRound2) StoreBroadcastMessage(round.Message) error {
	return nil
}
func (r *dummyRound2) Finalize(chan<- *round.Message) (round.Session, error) {
	return r.ResultRound("done"), nil
}
func (r *dummyRound2) MessageContent() round.Content              { return nil }
func (r *dummyRound2) BroadcastContent() round.BroadcastContent   { return &dummyContent{} }
func (r *dummyRound2) Number() round.Number                       { return 2 }

func dummyStart(ids []party.ID) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		helper, err := round.NewSession(round.Info{
			ProtocolID:       "test/dummy",
			FinalRoundNumber: 2,
			SelfID:           ids[0],
			PartyIDs:         ids,
			Threshold:        1,
			Group:            curve.Secp256k1{},
		}, sessionID, nil)
		if err != nil {
			return nil, err
		}
		return &dummyRound1{Helper: helper}, nil
	}
}

// Stop must abort a running session, and must be a no-op (not a panic, not a
// double close) once the session has finished, whether by result or abort.
func TestStop(t *testing.T) {
	ids := []party.ID{"a", "b"}

	newHandler := func(sessionID string) *protocol.MultiHandler {
		h, err := protocol.NewMultiHandler(dummyStart(ids), []byte(sessionID))
		require.NoError(t, err)
		return h
	}

	// Stop on a live session aborts it.
	h := newHandler("stop-test-session-1")
	broadcast, ok := <-h.Listen()
	require.True(t, ok, "expected the round 2 broadcast emitted at creation")
	require.Equal(t, round.Number(2), broadcast.RoundNumber)

	h.Stop()

	_, err := h.Result()
	require.Error(t, err, "Stop must abort a running session")
	abortMsg, ok := recvOrTimeout(t, h.Listen())
	require.True(t, ok, "expected an abort notification")
	assert.Equal(t, round.Number(0), abortMsg.RoundNumber)
	_, ok = recvOrTimeout(t, h.Listen())
	require.False(t, ok, "Listen must be closed after Stop")

	// Stop after completion is a no-op, not a panic on the closed channel.
	require.NotPanics(t, func() { h.Stop() })
	require.NotPanics(t, func() { h.Stop() })

	// The same holds after a natural (non-abort) completion.
	h2 := newHandler("stop-test-session-2")
	broadcast2, ok := <-h2.Listen()
	require.True(t, ok)
	h2.Accept(&protocol.Message{
		SSID:        broadcast2.SSID,
		From:        ids[1],
		To:          "",
		Protocol:    broadcast2.Protocol,
		RoundNumber: 2,
		Data:        broadcast2.Data,
		Broadcast:   true,
	})
	res, err := h2.Result()
	require.NoError(t, err)
	require.Equal(t, "done", res)
	require.NotPanics(t, func() { h2.Stop() })
}
