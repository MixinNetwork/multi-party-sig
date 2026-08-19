package keygen

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/internal/test"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/polynomial"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/pkg/pool"
	"github.com/fxamacker/cbor/v2"
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

// TestRound3RejectsSmallSubgroup drives an edwards25519 keygen to round 3 and
// asserts that VSS commitments and ElGamal keys carrying order-8 torsion are
// rejected before any key material is derived (RFC 9591, Section 6.1).
func TestRound3RejectsSmallSubgroup(t *testing.T) {
	group := curve.Edwards25519{}
	partyIDs := test.PartyIDs(3)
	sessionID := test.SessionID("r3-torsion")

	// round 1 → round 2, collecting each party's commitment
	b2s := make(map[party.ID]*broadcast2)
	r2s := make(map[party.ID]*round2)
	for _, id := range partyIDs {
		info := round.Info{
			ProtocolID:       "cmp/keygen-threshold",
			FinalRoundNumber: Rounds,
			SelfID:           id,
			PartyIDs:         partyIDs,
			Threshold:        1,
			Group:            group,
		}
		s, err := Start(info, nil)(sessionID)
		require.NoError(t, err)
		out := make(chan *round.Message, 4)
		next, err := s.Finalize(out)
		require.NoError(t, err)
		close(out)
		for m := range out {
			b2s[id] = m.Content.(*broadcast2)
		}
		r2s[id] = next.(*round2)
	}

	// round 2 → round 3, collecting every party's honest broadcast3
	b3s := make(map[party.ID]*broadcast3)
	var r3 *round3
	for _, id := range partyIDs {
		r2 := r2s[id]
		for _, from := range partyIDs {
			if from == id {
				continue
			}
			require.NoError(t, r2.StoreBroadcastMessage(round.Message{From: from, Content: b2s[from], Broadcast: true}))
		}
		out := make(chan *round.Message, 8)
		next, err := r2.Finalize(out)
		require.NoError(t, err)
		close(out)
		if id == partyIDs[0] {
			r3 = next.(*round3)
		}
		for m := range out {
			if m.Broadcast {
				b3s[id] = m.Content.(*broadcast3)
			}
		}
	}
	honestB3 := b3s[partyIDs[1]]
	require.NotNil(t, honestB3)

	// the order-8 torsion point on edwards25519
	torsionBytes, err := hex.DecodeString("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
	require.NoError(t, err)
	T8 := group.NewPoint()
	require.NoError(t, T8.UnmarshalBinary(torsionBytes))
	require.False(t, T8.IsIdentity())
	require.False(t, T8.IsInPrimeOrderGroup())

	// a VSS polynomial whose coefficients all carry torsion (built through
	// the wire format, as an attacker would)
	torsionPhi := torsionExponent(t, group, r3.Threshold(), T8)
	badPhi := *honestB3
	badPhi.VSSPolynomial = torsionPhi
	err = r3.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &badPhi, Broadcast: true})
	assert.ErrorContains(t, err, "prime-order subgroup")

	// a torsion ElGamal public key must be rejected too
	badElGamal := *honestB3
	badElGamal.ElGamalPublic = T8
	err = r3.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &badElGamal, Broadcast: true})
	assert.ErrorContains(t, err, "prime-order subgroup")

	// the honest broadcast still passes the subgroup checks
	require.NoError(t, r3.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: honestB3, Broadcast: true}))
}

// torsionExponent builds an Exponent of the given degree whose coefficients
// are honest points polluted with the given torsion point, through the wire
// format.
func torsionExponent(t *testing.T, group curve.Curve, degree int, T8 curve.Point) *polynomial.Exponent {
	t.Helper()
	coeffBytes := make([][]byte, degree+1)
	for k := range coeffBytes {
		p := sample.ScalarUnit(rand.Reader, group).ActOnBase().Add(T8)
		b, err := p.MarshalBinary()
		require.NoError(t, err)
		coeffBytes[k] = b
	}
	payload, err := cbor.Marshal(struct {
		IsConstant   bool
		Coefficients [][]byte
	}{false, coeffBytes})
	require.NoError(t, err)
	wire := make([]byte, 4+len(payload))
	wire[3] = byte(degree + 1)
	copy(wire[4:], payload)
	exp := polynomial.EmptyExponent(group)
	require.NoError(t, exp.UnmarshalBinary(wire))
	require.Equal(t, degree, exp.Degree())
	require.False(t, exp.IsInPrimeOrderGroup())
	return exp
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
