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
		r, err := StartSignCommon(false, result, partyIDs, steak)(nil)
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

	checkOutputEd25519(t, rounds, newPublicKey, steak)
}

func checkOutputEd25519(t *testing.T, rounds []round.Session, public curve.Point, m []byte) {
	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r, "expected result round")
		resultRound := r.(*round.Output)
		require.IsType(t, &Signature{}, resultRound.Result, "expected signature result")
		signature := resultRound.Result.(*Signature)
		assert.True(t, signature.Verify(public, m), "expected valid signature")

		pb, _ := public.MarshalBinary()
		assert.Len(t, pb, 32)
		pub := ed25519.PublicKey(pb)
		sig := signature.Bytes()
		assert.Len(t, sig, 64)
		assert.False(t, ed25519.Verify(pub, m, sig), "expected invalid ed25519 signature because hash method")

		var mpub crypto.Key
		copy(mpub[:], pb)
		var msig crypto.Signature
		copy(msig[:], sig)
		assert.Len(t, sig, 64)

		challengeHash := hash.New()
		_ = challengeHash.WriteAny(signature.R, public, messageHash(m))
		digest := challengeHash.Sum()
		x, _ := edwards25519.NewScalar().SetUniformBytes(digest[:])

		assert.True(t, mpub.VerifyWithChallenge(m, msig, x), "expected valid mixin signature")
	}
}
