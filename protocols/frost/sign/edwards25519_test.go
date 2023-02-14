package sign

import (
	"crypto/rand"
	"encoding/hex"
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
	testSignEdwards25519(t, ProtocolEd25519SHA512)
	testSignEdwards25519(t, ProtocolDefault)
	testSignEdwards25519(t, ProtocolMixinPublic)
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

	if variant == ProtocolMixinPublic {
		seed := sample.Scalar(rand.Reader, group).Bytes()
		mask, _ := hex.DecodeString("827e14ca58aec0759d3f31f0dc0725f766022fa89fa479dfbdf423d3a5bc4b64")
		var R crypto.Key
		copy(R[:], mask)
		index := uint64(0)
		a := crypto.NewKeyFromSeed(append(seed, seed...))
		mask = crypto.HashScalar(crypto.KeyMultPubPriv(&R, &a), index).Bytes()
		steak = append(mask, steak...)
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
		messageHash := steak
		r, err := StartSignCommon(result, partyIDs, messageHash, variant)(nil)
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

		switch variant {
		case ProtocolEd25519SHA512:
			assert.True(t, signature.VerifyEd25519(public, m), "expected valid ed25519 signature")
		case ProtocolMixinPublic:
			group := curve.Edwards25519{}
			r := group.NewScalar()
			r.UnmarshalBinary(m[:32])
			P := r.ActOnBase().Add(public)
			assert.True(t, signature.VerifyEd25519(P, m[32:]), "expected valid mixin signature")
		default:
			assert.False(t, signature.VerifyEd25519(public, m), "expected invalid ed25519 signature")
		}

		pb, _ := public.MarshalBinary()
		assert.Len(t, pb, 32)
		sig := signature.Serialize()
		assert.Len(t, sig, 64)
		var mpub crypto.Key
		copy(mpub[:], pb)
		var msig crypto.Signature
		copy(msig[:], sig)
		assert.Len(t, sig, 64)
		switch variant {
		case ProtocolEd25519SHA512:
			assert.True(t, mpub.Verify(m, msig), "expected valid ed25519 signature")
		case ProtocolDefault:
			challengeHash := hash.New()
			_ = challengeHash.WriteAny(signature.R, public, messageHash(m))
			digest := challengeHash.Sum()
			x, _ := edwards25519.NewScalar().SetUniformBytes(digest[:])
			assert.True(t, mpub.VerifyWithChallenge(m, msig, x), "expected valid ed25519 signature")
		}
	}
}
