package sign

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/internal/test"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost/keygen"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func signRounds(t *testing.T, variant int) (round.Session, round.Session) {
	t.Helper()
	var group curve.Curve
	if variant == ProtocolEd25519SHA512 || variant == ProtocolMixinPublic {
		group = curve.Edwards25519{}
	} else {
		group = curve.Secp256k1{}
	}
	partyIDs := test.PartyIDs(3)
	secret := sample.Scalar(tR, group)
	shares := make(map[party.ID]curve.Scalar)
	verificationShares := make(map[party.ID]curve.Point)
	for _, id := range partyIDs {
		share := sample.Scalar(tR, group)
		shares[id] = share
		verificationShares[id] = share.ActOnBase()
	}
	config := &keygen.Config{
		ID:                 partyIDs[0],
		Threshold:          2,
		PrivateShare:       shares[partyIDs[0]],
		PublicKey:          secret.ActOnBase(),
		ChainKey:           make([]byte, 32),
		VerificationShares: party.NewPointMap(verificationShares),
	}
	r1, err := StartSignCommon(config, partyIDs, []byte("message"), variant)(test.SessionID("iface"))
	require.NoError(t, err)

	out := make(chan *round.Message, 4)
	r2, err := r1.Finalize(out)
	require.NoError(t, err)
	close(out)
	return r1, r2
}

var tR = readerFunc{}

type readerFunc struct{}

func (readerFunc) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i * 7)
	}
	return len(p), nil
}

func TestRoundInterfaceMethods(t *testing.T) {
	for _, variant := range []int{ProtocolDefault, ProtocolTaproot, ProtocolEd25519SHA512} {
		r1, r2 := signRounds(t, variant)

		// round1 methods
		assert.Equal(t, round.Number(1), r1.Number())
		assert.Nil(t, r1.MessageContent())
		assert.NoError(t, r1.VerifyMessage(round.Message{}))
		assert.NoError(t, r1.StoreMessage(round.Message{}))

		// round2 methods
		assert.Equal(t, round.Number(2), r2.Number())
		assert.Nil(t, r2.MessageContent())
		assert.NoError(t, r2.VerifyMessage(round.Message{}))
		assert.NoError(t, r2.StoreMessage(round.Message{}))
	}
}

func TestRound2StoreBroadcastErrors(t *testing.T) {
	group := curve.Secp256k1{}
	_, r2 := signRounds(t, ProtocolDefault)
	partyIDs := test.PartyIDs(3)

	// wrong content type
	err := r2.(*round2).StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &broadcast3{}})
	assert.ErrorIs(t, err, round.ErrInvalidContent)

	// identity commitments must be rejected
	err = r2.(*round2).StoreBroadcastMessage(round.Message{
		From:    partyIDs[1],
		Content: &broadcast2{D_i: group.NewPoint(), E_i: group.NewBasePoint()},
	})
	assert.Error(t, err)

	err = r2.(*round2).StoreBroadcastMessage(round.Message{
		From:    partyIDs[1],
		Content: &broadcast2{D_i: group.NewBasePoint(), E_i: group.NewPoint()},
	})
	assert.Error(t, err)

	// nil commitments must be rejected cleanly (no panic)
	err = r2.(*round2).StoreBroadcastMessage(round.Message{
		From:    partyIDs[1],
		Content: &broadcast2{},
	})
	assert.ErrorIs(t, err, round.ErrNilFields)
}

func TestRound2StoreBroadcastRejectsSmallSubgroup(t *testing.T) {
	edwards := curve.Edwards25519{}
	_, r2 := signRounds(t, ProtocolEd25519SHA512)
	partyIDs := test.PartyIDs(3)

	// a torsion (order-8) nonce commitment must be rejected on edwards25519
	torsionBytes, err := hex.DecodeString("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
	require.NoError(t, err)
	T8 := edwards.NewPoint()
	require.NoError(t, T8.UnmarshalBinary(torsionBytes))

	err = r2.(*round2).StoreBroadcastMessage(round.Message{
		From:    partyIDs[1],
		Content: &broadcast2{D_i: T8, E_i: edwards.NewBasePoint()},
	})
	assert.ErrorContains(t, err, "prime-order subgroup")

	err = r2.(*round2).StoreBroadcastMessage(round.Message{
		From:    partyIDs[1],
		Content: &broadcast2{D_i: edwards.NewBasePoint(), E_i: T8},
	})
	assert.ErrorContains(t, err, "prime-order subgroup")

	// a prime-order commitment polluted with torsion is rejected as well
	polluted := edwards.NewBasePoint().Add(T8)
	err = r2.(*round2).StoreBroadcastMessage(round.Message{
		From:    partyIDs[1],
		Content: &broadcast2{D_i: polluted, E_i: edwards.NewBasePoint()},
	})
	assert.ErrorContains(t, err, "prime-order subgroup")

	// honest commitments still pass
	honestD := sample.Scalar(tR, edwards).ActOnBase()
	err = r2.(*round2).StoreBroadcastMessage(round.Message{
		From:    partyIDs[1],
		Content: &broadcast2{D_i: honestD, E_i: edwards.NewBasePoint()},
	})
	assert.NoError(t, err)
}

func TestRound3InterfaceMethods(t *testing.T) {
	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(3)

	secret := sample.Scalar(tR, group)
	configs := make([]*keygen.Config, 0, 3)
	shares := make(map[party.ID]curve.Scalar)
	verificationShares := make(map[party.ID]curve.Point)
	for _, id := range partyIDs {
		share := sample.Scalar(tR, group)
		shares[id] = share
		verificationShares[id] = share.ActOnBase()
	}
	for _, id := range partyIDs {
		configs = append(configs, &keygen.Config{
			ID:                 id,
			Threshold:          2,
			PrivateShare:       shares[id],
			PublicKey:          secret.ActOnBase(),
			ChainKey:           make([]byte, 32),
			VerificationShares: party.NewPointMap(verificationShares),
		})
	}

	rounds := make([]round.Session, 0, 3)
	for _, cfg := range configs {
		r, err := StartSignCommon(cfg, partyIDs, []byte("message"), ProtocolDefault)(test.SessionID("r3"))
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
	assert.Nil(t, r3.MessageContent())
	assert.NoError(t, r3.VerifyMessage(round.Message{}))
	assert.NoError(t, r3.StoreMessage(round.Message{}))

	// wrong content type in broadcast
	err := r3.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &broadcast2{}})
	assert.ErrorIs(t, err, round.ErrInvalidContent)

	// nil Z_i must be rejected
	err = r3.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &broadcast3{Z_i: nil}})
	assert.ErrorIs(t, err, round.ErrNilFields)

	// an invalid response must be rejected
	wrong := sample.Scalar(tR, group)
	err = r3.StoreBroadcastMessage(round.Message{From: partyIDs[1], Content: &broadcast3{Z_i: wrong}})
	assert.Error(t, err)
}

func TestRound3Finalize_AbortsOnBadSignature(t *testing.T) {
	// both protocol variants, several sessions: this also exercises the
	// parity-dependent taproot negation branches with overwhelming probability
	for _, variant := range []int{ProtocolDefault, ProtocolTaproot} {
		for session := 0; session < 4; session++ {
			testRound3AbortOnce(t, variant, session)
		}
	}
}

func testRound3AbortOnce(t *testing.T, variant, session int) {
	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(3)

	secret := sample.Scalar(tR, group)
	shares := make(map[party.ID]curve.Scalar)
	verificationShares := make(map[party.ID]curve.Point)
	for _, id := range partyIDs {
		share := sample.Scalar(tR, group)
		shares[id] = share
		verificationShares[id] = share.ActOnBase()
	}

	rounds := make([]round.Session, 0, 3)
	for _, id := range partyIDs {
		config := &keygen.Config{
			ID:                 id,
			Threshold:          2,
			PrivateShare:       shares[id],
			PublicKey:          secret.ActOnBase(),
			ChainKey:           make([]byte, 32),
			VerificationShares: party.NewPointMap(verificationShares),
		}
		r, err := StartSignCommon(config, partyIDs, []byte("message"), variant)(test.SessionID(fmt.Sprintf("abort-%d-%d", variant, session)))
		require.NoError(t, err)
		rounds = append(rounds, r)
	}

	// advance to round 3 with all stores complete
	r, done := test.Rounds(rounds, nil)
	require.NoError(t, r)
	require.False(t, done)
	r, done = test.Rounds(rounds, nil)
	require.NoError(t, r)
	require.False(t, done)

	// tamper with the accumulated responses so the final signature fails
	r3 := rounds[0].(*round3)
	require.NotEmpty(t, r3.z)
	for id := range r3.z {
		r3.z[id] = group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1))
	}

	out := make(chan *round.Message, 1)
	next, err := r3.Finalize(out)
	require.NoError(t, err)
	require.IsType(t, &round.Abort{}, next, "expected an abort when the signature fails to verify")
}

func testVerificationShares(group curve.Curve, partyIDs []party.ID) *party.PointMap {
	shares := make(map[party.ID]curve.Point, len(partyIDs))
	for _, id := range partyIDs {
		shares[id] = sample.Scalar(tR, group).ActOnBase()
	}
	return party.NewPointMap(shares)
}

func TestStartSignCommon_MixinPublicShortMessage(t *testing.T) {
	group := curve.Edwards25519{}
	partyIDs := test.PartyIDs(3)
	secret := sample.Scalar(tR, group)
	config := &keygen.Config{
		ID:                 partyIDs[0],
		Threshold:          2,
		PrivateShare:       sample.Scalar(tR, group),
		PublicKey:          secret.ActOnBase(),
		ChainKey:           make([]byte, 32),
		VerificationShares: testVerificationShares(group, partyIDs),
	}

	// MixinPublic requires at least 32 bytes of message
	_, err := StartSignCommon(config, partyIDs, []byte("short"), ProtocolMixinPublic)(test.SessionID("mixin"))
	assert.Error(t, err)

	// a valid-length message parses the mask scalar and starts
	long := make([]byte, 40)
	_, err = StartSignCommon(config, partyIDs, long, ProtocolMixinPublic)(test.SessionID("mixin"))
	assert.NoError(t, err)
}

func TestStartSignCommon_InvalidSession(t *testing.T) {
	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(3)
	secret := sample.Scalar(tR, group)
	config := &keygen.Config{
		ID:                 "zz", // not in the signers list
		Threshold:          2,
		PrivateShare:       sample.Scalar(tR, group),
		PublicKey:          secret.ActOnBase(),
		ChainKey:           make([]byte, 32),
		VerificationShares: testVerificationShares(group, partyIDs),
	}

	// the self ID must be part of the signers
	_, err := StartSignCommon(config, partyIDs, []byte("m"), ProtocolDefault)(test.SessionID("bad-session"))
	assert.Error(t, err)

	// a short session ID must be rejected
	config.ID = partyIDs[0]
	_, err = StartSignCommon(config, partyIDs, []byte("m"), ProtocolDefault)([]byte("short"))
	assert.Error(t, err)
}

func TestRound1Finalize_OutChanFull(t *testing.T) {
	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(3)
	secret := sample.Scalar(tR, group)
	config := &keygen.Config{
		ID:                 partyIDs[0],
		Threshold:          2,
		PrivateShare:       sample.Scalar(tR, group),
		PublicKey:          secret.ActOnBase(),
		ChainKey:           make([]byte, 32),
		VerificationShares: testVerificationShares(group, partyIDs),
	}
	r1, err := StartSignCommon(config, partyIDs, []byte("m"), ProtocolDefault)(test.SessionID("full"))
	require.NoError(t, err)

	// an unbuffered channel makes the broadcast fail
	next, err := r1.Finalize(make(chan *round.Message))
	require.Error(t, err)
	require.NotNil(t, next)
}

func TestMessageHash_WriteTo(t *testing.T) {
	// a nil message hash must error
	_, err := messageHash(nil).WriteTo(&nullWriter{})
	assert.Error(t, err)

	// a real message hash writes its bytes
	w := &countingWriter{}
	n, err := messageHash("abc").WriteTo(w)
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)
	assert.Equal(t, "messageHash", messageHash(nil).Domain())
}

type nullWriter struct{}

func (*nullWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

type countingWriter struct {
	total int
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.total += len(p)
	return len(p), nil
}
