package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"filippo.io/edwards25519"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/multi-party-sig/common/params"
	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/internal/test"
	"github.com/MixinNetwork/multi-party-sig/pkg/hash"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/polynomial"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost/keygen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignEdwards25519(t *testing.T) {
	testSignEdwards25519(t, ProtocolMixin)
	testSignEdwards25519(t, ProtocolDefault)
}

func testSignEdwards25519(t *testing.T, variant int) {
	group := curve.Edwards25519{}

	N := 5
	threshold := 2

	partyIDs := test.PartyIDs(N)

	secret := sample.Scalar(rand.Reader, group)
	f := polynomial.NewPolynomial(group, threshold, secret)
	publicKey := secret.ActOnBase()
	steak := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	chainKey := make([]byte, params.SecBytes)
	_, _ = rand.Read(chainKey)

	privateShares := make(map[party.ID]curve.Scalar, N)
	for _, id := range partyIDs {
		privateShares[id] = f.Evaluate(id.Scalar(group))
	}

	verificationShares := make(map[party.ID]curve.Point, N)
	for _, id := range partyIDs {
		verificationShares[id] = privateShares[id].ActOnBase()
	}

	var newPublicKey curve.Point
	rounds := make([]round.Session, 0, N)
	for _, id := range partyIDs {
		result := &keygen.Config{
			ID:                 id,
			Threshold:          threshold,
			PublicKey:          publicKey,
			PrivateShare:       privateShares[id],
			VerificationShares: party.NewPointMap(verificationShares),
			ChainKey:           chainKey,
		}
		if newPublicKey == nil {
			newPublicKey = result.PublicKey
		}
		r, err := StartSignCommon(result, partyIDs, steak, variant)(nil)
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

	checkOutputEd25519(t, rounds, newPublicKey, steak, variant)
}

func checkOutputEd25519(t *testing.T, rounds []round.Session, public curve.Point, m []byte, variant int) {
	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r, "expected result round")
		resultRound := r.(*round.Output)
		require.IsType(t, &Signature{}, resultRound.Result, "expected signature result")
		signature := resultRound.Result.(*Signature)
		switch variant {
		case ProtocolDefault:
			assert.True(t, signature.Verify(public, m), "expected valid signature")
		default:
			assert.False(t, signature.Verify(public, m), "expected invalid signature")
		}

		pb, _ := public.MarshalBinary()
		assert.Len(t, pb, 32)
		pub := ed25519.PublicKey(pb)
		sig := signature.Bytes()
		assert.Len(t, sig, 64)
		switch variant {
		case ProtocolMixin:
			assert.True(t, ed25519.Verify(pub, m, sig), "expected valid ed25519 signature")
		default:
			assert.False(t, ed25519.Verify(pub, m, sig), "expected invalid ed25519 signature")
		}

		var mpub crypto.Key
		copy(mpub[:], pb)
		var msig crypto.Signature
		copy(msig[:], sig)
		assert.Len(t, sig, 64)
		switch variant {
		case ProtocolMixin:
			assert.True(t, mpub.Verify(m, msig), "expected valid mixin signature")
		case ProtocolDefault:
			challengeHash := hash.New()
			_ = challengeHash.WriteAny(signature.R, public, messageHash(m))
			digest := challengeHash.Sum()
			x, _ := edwards25519.NewScalar().SetUniformBytes(digest[:])
			assert.True(t, mpub.VerifyWithChallenge(m, msig, x), "expected valid mixin signature")
		}
	}
}
