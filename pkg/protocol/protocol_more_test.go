package protocol_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/pkg/protocol"
	"github.com/MixinNetwork/multi-party-sig/protocols/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMultiHandler_BadStartFunc(t *testing.T) {
	_, err := protocol.NewMultiHandler(func(sessionID []byte) (round.Session, error) {
		return nil, errors.New("boom")
	}, []byte("some session id!!"))
	assert.Error(t, err)
}

type handlers struct {
	a, b *protocol.MultiHandler
}

func newTwoParties(t *testing.T) handlers {
	t.Helper()
	group := curve.Secp256k1{}
	ids := []party.ID{"a", "b"}
	sessionID := []byte("protocol-test-1234")
	hA, err := protocol.NewMultiHandler(cmp.Keygen(group, "a", ids, 1, nil), sessionID)
	require.NoError(t, err)
	hB, err := protocol.NewMultiHandler(cmp.Keygen(group, "b", ids, 1, nil), sessionID)
	require.NoError(t, err)
	return handlers{a: hA, b: hB}
}

func drain(h *protocol.MultiHandler) []*protocol.Message {
	var out []*protocol.Message
	for {
		select {
		case m, ok := <-h.Listen():
			if !ok {
				return out
			}
			out = append(out, m)
		default:
			return out
		}
	}
}

func TestMultiHandler_String(t *testing.T) {
	hs := newTwoParties(t)
	s := hs.a.String()
	assert.Contains(t, s, "a")
	assert.Contains(t, s, "cmp/keygen")
}

func TestMultiHandler_ResultNotFinished(t *testing.T) {
	hs := newTwoParties(t)
	_, err := hs.a.Result()
	assert.Error(t, err)
	assert.Equal(t, "protocol: not finished", err.Error())
}

func TestMultiHandler_CanAccept(t *testing.T) {
	hs := newTwoParties(t)
	msgs := drain(hs.a)
	require.NotEmpty(t, msgs)
	bcast := msgs[0]
	hB := hs.b

	// nil is rejected
	assert.False(t, hB.CanAccept(nil))

	// a genuine message is accepted (unless it is a self message)
	if !bcast.IsFor("b") {
		assert.True(t, hB.CanAccept(bcast))
	}

	// wrong protocol
	wrong := *bcast
	wrong.Protocol = "other"
	assert.False(t, hB.CanAccept(&wrong))

	// wrong SSID
	wrong = *bcast
	wrong.SSID = []byte("bad ssid")
	assert.False(t, hB.CanAccept(&wrong))

	// unknown sender
	wrong = *bcast
	wrong.From = "zz"
	assert.False(t, hB.CanAccept(&wrong))

	// nil data
	wrong = *bcast
	wrong.Data = nil
	assert.False(t, hB.CanAccept(&wrong))

	// round number too large
	wrong = *bcast
	wrong.RoundNumber = 99
	assert.False(t, hB.CanAccept(&wrong))

	// message not for us
	wrong = *bcast
	wrong.To = "c"
	assert.False(t, hB.CanAccept(&wrong))

	// a message from ourselves is not for us
	wrong = *bcast
	wrong.From = "b"
	if !wrong.Broadcast {
		wrong.To = "b"
	}
	assert.False(t, hB.CanAccept(&wrong))
}

// A round-0 abort notification must not cause the receiving party to blame
// its sender as a culprit: the sender may be an honest party forwarding a
// failure it detected elsewhere, and a malicious party could otherwise frame
// honest parties by forwarding aborts. Culprits may only come from locally
// verified evidence. The sender is still named in the error message, since
// having received the abort from them is a verifiable fact.
func TestMultiHandler_AcceptAbortFromOtherParty(t *testing.T) {
	hs := newTwoParties(t)
	msgs := drain(hs.a)
	require.NotEmpty(t, msgs)
	good := msgs[0]

	abortMsg := &protocol.Message{
		SSID:        good.SSID,
		From:        "a",
		To:          "b",
		Protocol:    good.Protocol,
		RoundNumber: 0,
		Data:        []byte("I abort"),
	}
	assert.True(t, hs.b.CanAccept(abortMsg))

	hs.b.Accept(abortMsg)
	_, err := hs.b.Result()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aborted by other party")
	assert.Contains(t, err.Error(), `"a"`)
	assert.Contains(t, err.Error(), "I abort")

	var perr protocol.Error
	require.ErrorAs(t, err, &perr)
	assert.Empty(t, perr.Culprits, "a forwarded abort must not blame the forwarding party")
}

func TestMultiHandler_Stop(t *testing.T) {
	hs := newTwoParties(t)
	msgs := drain(hs.a)
	require.NotEmpty(t, msgs)
	good := msgs[0]

	hs.a.Stop()

	// stopping aborts the protocol
	_, err := hs.a.Result()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aborted by user")

	// the out channel is closed (a final abort message may be buffered first)
	for {
		_, open := <-hs.a.Listen()
		if !open {
			break
		}
	}

	// a second Stop is a no-op
	hs.a.Stop()

	// messages are no longer accepted
	msg := &protocol.Message{
		SSID:        good.SSID,
		From:        "b",
		To:          "a",
		Protocol:    good.Protocol,
		RoundNumber: 1,
		Data:        []byte("x"),
	}
	hs.a.Accept(msg) // must be ignored without panic
}

func TestMultiHandler_AcceptDuplicate(t *testing.T) {
	hs := newTwoParties(t)
	msgs := drain(hs.a)
	var bcast *protocol.Message
	for _, m := range msgs {
		if m.Broadcast {
			bcast = m
			break
		}
	}
	require.NotNil(t, bcast)

	// accepting the same message twice must not panic; the second is a duplicate
	hs.b.Accept(bcast)
	hs.b.Accept(bcast)
}

func TestMessage_StringHashIsFor(t *testing.T) {
	m := &protocol.Message{
		SSID:        []byte("ssid"),
		From:        "a",
		To:          "",
		Protocol:    "test/proto",
		RoundNumber: 2,
		Data:        []byte("data"),
		Broadcast:   true,
	}
	assert.Contains(t, m.String(), "test/proto")

	// IsFor semantics
	assert.False(t, m.IsFor("a"), "a message is not for its sender")
	assert.True(t, m.IsFor("b"), "a broadcast is for everyone")
	m.To = "b"
	assert.True(t, m.IsFor("b"))
	assert.False(t, m.IsFor("c"))

	// Hash is deterministic and sensitive to all fields
	h1 := m.Hash()
	h2 := m.Hash()
	assert.Equal(t, h1, h2)
	assert.Len(t, h1, 64)

	m.Broadcast = false
	assert.NotEqual(t, h1, m.Hash())
}

func TestMessage_MarshalRoundTrip(t *testing.T) {
	m := &protocol.Message{
		SSID:                  []byte("ssid"),
		From:                  "a",
		To:                    "b",
		Protocol:              "test/proto",
		RoundNumber:           3,
		Data:                  []byte("payload"),
		Broadcast:             true,
		BroadcastVerification: []byte("verification"),
	}
	data, err := m.MarshalBinary()
	require.NoError(t, err)

	m2 := &protocol.Message{}
	require.NoError(t, m2.UnmarshalBinary(data))
	assert.Equal(t, m.SSID, m2.SSID)
	assert.Equal(t, m.From, m2.From)
	assert.Equal(t, m.To, m2.To)
	assert.Equal(t, m.Protocol, m2.Protocol)
	assert.Equal(t, m.RoundNumber, m2.RoundNumber)
	assert.Equal(t, m.Data, m2.Data)
	assert.Equal(t, m.Broadcast, m2.Broadcast)
	assert.Equal(t, m.BroadcastVerification, m2.BroadcastVerification)

	// invalid cbor must error
	assert.Error(t, m2.UnmarshalBinary([]byte{0xff}))
}

func TestError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("inner failure")

	// without culprits
	e := protocol.Error{Err: inner}
	assert.Equal(t, "inner failure", e.Error())
	assert.Equal(t, inner, e.Unwrap())
	assert.ErrorIs(t, e, inner)

	// with culprits
	e = protocol.Error{Culprits: []party.ID{"a"}, Err: inner}
	assert.Contains(t, e.Error(), "a")
	assert.Contains(t, e.Error(), "inner failure")
	assert.ErrorIs(t, e, inner)
}

func TestMessage_EqualBytes(t *testing.T) {
	// two identical messages must produce identical hashes
	a := &protocol.Message{SSID: []byte("s"), From: "a", Protocol: "p", RoundNumber: 1, Data: []byte("d")}
	b := &protocol.Message{SSID: bytes.Clone([]byte("s")), From: "a", Protocol: "p", RoundNumber: 1, Data: []byte("d")}
	assert.Equal(t, a.Hash(), b.Hash())
}

// TestMultiHandler_FullExchange runs a complete two-party CMP keygen through
// two MultiHandlers wired together, covering the message verification and
// round finalization paths.
func TestMultiHandler_AcceptCorruptData(t *testing.T) {
	hs := newTwoParties(t)
	msgs := drain(hs.a)
	require.NotEmpty(t, msgs)
	var bcast *protocol.Message
	for _, m := range msgs {
		if m.Broadcast {
			bcast = m
			break
		}
	}
	require.NotNil(t, bcast)

	// corrupt the payload: the header still passes CanAccept, but the
	// content fails to unmarshal, aborting with the sender as culprit
	corrupt := *bcast
	corrupt.Data = []byte{0xff, 0x00, 0x01}
	require.True(t, hs.b.CanAccept(&corrupt))
	hs.b.Accept(&corrupt)

	_, err := hs.b.Result()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal")
}

func TestMultiHandler_BroadcastHashMismatch(t *testing.T) {
	group := curve.Secp256k1{}
	ids := []party.ID{"a", "b"}
	sessionID := []byte("protocol-hash-1234")

	hs := map[party.ID]*protocol.MultiHandler{}
	for _, id := range ids {
		h, err := protocol.NewMultiHandler(cmp.Keygen(group, id, ids, 1, nil), sessionID)
		require.NoError(t, err)
		hs[id] = h
	}

	// run one full exchange, but tamper the broadcast verification of the
	// round-2 messages sent by B
	round := 0
	for round < 20 {
		var outgoing []*protocol.Message
		for _, h := range hs {
			outgoing = append(outgoing, drain(h)...)
		}
		if len(outgoing) == 0 {
			break
		}
		allDone := true
		for _, h := range hs {
			select {
			case _, open := <-h.Listen():
				if open {
					allDone = false
				}
			default:
				allDone = false
			}
		}
		if allDone {
			break
		}
		for _, msg := range outgoing {
			if msg.From == "b" && msg.RoundNumber >= 2 && msg.BroadcastVerification != nil {
				tampered := *msg
				tampered.BroadcastVerification = []byte("wrong hash")
				msg = &tampered
			}
			for _, h := range hs {
				if h.CanAccept(msg) {
					h.Accept(msg)
				}
			}
		}
		round++
	}

	// A must detect the mismatch and abort; B may legitimately finish since
	// it only sees genuine messages from A
	_, err := hs["a"].Result()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broadcast verification failed")
}

// TestMultiHandler_QueuedCorruptFutureMessage delivers a corrupt message for a
// future round; it must be stored, then trigger an abort when its round starts.
func TestMultiHandler_QueuedCorruptFutureMessage(t *testing.T) {
	group := curve.Secp256k1{}
	ids := []party.ID{"a", "b"}
	sessionID := []byte("protocol-queue-123")

	hs := map[party.ID]*protocol.MultiHandler{}
	for _, id := range ids {
		h, err := protocol.NewMultiHandler(cmp.Keygen(group, id, ids, 1, nil), sessionID)
		require.NoError(t, err)
		hs[id] = h
	}

	// collect round-1 messages and note the SSID
	var round1 []*protocol.Message
	for _, h := range hs {
		round1 = append(round1, drain(h)...)
	}
	require.NotEmpty(t, round1)

	// deliver a corrupt message claiming to be from round 2
	corrupt := &protocol.Message{
		SSID:        round1[0].SSID,
		From:        "a",
		Protocol:    round1[0].Protocol,
		RoundNumber: 2,
		Data:        []byte{0xff, 0x00},
		Broadcast:   true,
	}
	require.True(t, hs["b"].CanAccept(corrupt))
	hs["b"].Accept(corrupt)

	// a corrupt p2p message for a future round is stored as well
	corruptP2P := &protocol.Message{
		SSID:        round1[0].SSID,
		From:        "a",
		To:          "b",
		Protocol:    round1[0].Protocol,
		RoundNumber: 4,
		Data:        []byte{0xff, 0x00},
	}
	require.True(t, hs["b"].CanAccept(corruptP2P))
	hs["b"].Accept(corruptP2P)

	// run the exchange normally; when round 2 starts, the queued corrupt
	// message must be rejected and abort the protocol
	remaining := round1
	for round := 0; round < 10; round++ {
		var outgoing []*protocol.Message
		for _, h := range hs {
			outgoing = append(outgoing, drain(h)...)
		}
		if len(outgoing) == 0 && len(remaining) == 0 {
			break
		}
		outgoing = append(outgoing, remaining...)
		remaining = nil
		for _, msg := range outgoing {
			for _, h := range hs {
				if h.CanAccept(msg) {
					h.Accept(msg)
				}
			}
		}
	}

	_, err := hs["b"].Result()
	require.Error(t, err)
}

// TestMultiHandler_MessageForFutureRound accepts a p2p message for a future
// round while the current round is not finished.
func TestMultiHandler_MessageForFutureRound(t *testing.T) {
	hs := newTwoParties(t)
	msgs := drain(hs.a)
	require.NotEmpty(t, msgs)
	good := msgs[0]

	// a message for a future round is accepted and stored without processing
	future := *good
	future.RoundNumber = 3
	future.Broadcast = false
	future.To = "b"
	future.Data = []byte{0x01}
	if hs.b.CanAccept(&future) {
		hs.b.Accept(&future)
	}

	// the handler must still be unfinished and usable
	_, err := hs.b.Result()
	assert.Error(t, err) // "not finished"

	// once the current round advances, a message for a past round is rejected
	group := curve.Secp256k1{}
	sessionID2 := []byte("protocol-past-1234")
	h2a, err := protocol.NewMultiHandler(cmp.Keygen(group, "a", []party.ID{"a", "b"}, 1, nil), sessionID2)
	require.NoError(t, err)
	h2b, err := protocol.NewMultiHandler(cmp.Keygen(group, "b", []party.ID{"a", "b"}, 1, nil), sessionID2)
	require.NoError(t, err)

	// exchange round 1 so that both advance
	var r1msgs []*protocol.Message
	r1msgs = append(r1msgs, drain(h2a)...)
	r1msgs = append(r1msgs, drain(h2b)...)
	for _, msg := range r1msgs {
		if h2a.CanAccept(msg) {
			h2a.Accept(msg)
		}
		if h2b.CanAccept(msg) {
			h2b.Accept(msg)
		}
	}
	// both handlers are now in round 2; a round-1 message must be rejected
	past := *msgs[0]
	assert.False(t, h2b.CanAccept(&past), "message for a past round must be rejected")
}

func TestMultiHandler_FullExchange(t *testing.T) {
	if testing.Short() {
		t.Skip("requires full keygen")
	}
	group := curve.Secp256k1{}
	ids := []party.ID{"a", "b"}
	sessionID := []byte("protocol-full-1234")

	hs := map[party.ID]*protocol.MultiHandler{}
	for _, id := range ids {
		h, err := protocol.NewMultiHandler(cmp.Keygen(group, id, ids, 1, nil), sessionID)
		require.NoError(t, err)
		hs[id] = h
	}

	for round := 0; round < 20; round++ {
		// collect all outgoing messages
		var outgoing []*protocol.Message
		for _, h := range hs {
			outgoing = append(outgoing, drain(h)...)
		}
		if len(outgoing) == 0 {
			break
		}

		done := 0
		for _, h := range hs {
			select {
			case _, open := <-h.Listen():
				if !open {
					done++
				}
			default:
			}
		}
		if done == len(hs) {
			break
		}

		// deliver each message to everyone who can accept it
		for _, msg := range outgoing {
			for _, h := range hs {
				if h.CanAccept(msg) {
					h.Accept(msg)
				}
			}
		}
	}

	// both handlers must have produced a result
	for _, h := range hs {
		result, err := h.Result()
		require.NoError(t, err)
		require.IsType(t, &cmp.Config{}, result)
	}

	// the two configs must share the same public key
	resA, err := hs["a"].Result()
	require.NoError(t, err)
	resB, err := hs["b"].Result()
	require.NoError(t, err)
	cfgA := resA.(*cmp.Config)
	cfgB := resB.(*cmp.Config)
	assert.True(t, cfgA.PublicPoint().Equal(cfgB.PublicPoint()))
}
