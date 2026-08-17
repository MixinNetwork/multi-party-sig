package sign

import (
	mrand "math/rand"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/internal/test"
	"github.com/MixinNetwork/multi-party-sig/pkg/ecdsa"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/pool"
	"github.com/MixinNetwork/multi-party-sig/pkg/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestRound(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	group := curve.Secp256k1{}

	N := 6
	T := N - 1

	t.Log("generating configs")
	configs, partyIDs := test.GenerateConfig(group, N, T, mrand.New(mrand.NewSource(1)), pl)
	t.Log("done generating configs")

	partyIDs = partyIDs[:T+1]
	publicPoint := configs[partyIDs[0]].PublicPoint()

	messageToSign := []byte("hello")
	messageHash := make([]byte, 64)
	sha3.ShakeSum128(messageHash, messageToSign)

	rounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		c := configs[partyID]
		r, err := StartSign(c, partyIDs, messageHash, pl)(test.SessionID("cmp-sign-round-test"))
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)
	}

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r, "expected result round")
		resultRound := r.(*round.Output)
		require.IsType(t, &ecdsa.Signature{}, resultRound.Result, "expected taproot signature result")
		signature := resultRound.Result.(*ecdsa.Signature)
		assert.True(t, signature.Verify(publicPoint, messageHash), "expected valid signature")
	}
}

// TestSignEmptyToRejected is a regression test for a remote DoS: a non-broadcast
// message with an empty To field used to pass CanAccept and then cause a nil
// pointer dereference (panic) in the round's VerifyMessage, because maps were
// indexed with the empty To. Such messages must now be rejected by CanAccept,
// and Accept must not panic.
func TestSignEmptyToRejected(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	group := curve.Secp256k1{}

	N := 2
	T := N - 1

	configs, partyIDs := test.GenerateConfig(group, N, T, mrand.New(mrand.NewSource(1)), pl)
	idA, idB := partyIDs[0], partyIDs[1]

	messageHash := make([]byte, 64)
	sha3.ShakeSum128(messageHash, []byte("hello"))
	sessionID := test.SessionID("cmp-sign-empty-to-test")

	hA, err := protocol.NewMultiHandler(StartSign(configs[idA], partyIDs, messageHash, pl), sessionID)
	require.NoError(t, err)
	hB, err := protocol.NewMultiHandler(StartSign(configs[idB], partyIDs, messageHash, pl), sessionID)
	require.NoError(t, err)

	// cross-deliver round-2 messages so that both parties reach round 2,
	// then deliver B's round-3 broadcast so that A is in round 3 with B's
	// broadcast stored.
	var msgsB []*protocol.Message
	pump := func(from, to *protocol.MultiHandler) {
		for {
			select {
			case m := <-from.Listen():
				msgsB = append(msgsB, m)
				if m.RoundNumber == 2 || (m.RoundNumber == 3 && m.Broadcast) {
					cp := *m
					to.Accept(&cp)
				}
			default:
				return
			}
		}
	}
	pump(hA, hB)
	msgsB = nil
	pump(hB, hA)
	pump(hA, hB)

	var bToA3 *protocol.Message
	for _, m := range msgsB {
		if m.RoundNumber == 3 && !m.Broadcast && m.To == idA {
			bToA3 = m
		}
	}
	require.NotNil(t, bToA3, "expected a p2p round-3 message from B")

	// replay B's message with an empty To field: it must be rejected
	evil := &protocol.Message{
		SSID:        bToA3.SSID,
		From:        idB,
		To:          "",
		Protocol:    bToA3.Protocol,
		RoundNumber: 3,
		Data:        bToA3.Data,
		Broadcast:   false,
	}
	assert.False(t, hA.CanAccept(evil), "p2p message with empty To must not be accepted")
	assert.NotPanics(t, func() { hA.Accept(evil) }, "Accept must not panic on empty To")

	// the protocol must still be able to complete for A afterwards
	assert.NotPanics(t, func() { hA.Accept(bToA3) })
}
