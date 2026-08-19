package keygen

// Regression tests for the prime-order subgroup validation in
// Config.UnmarshalBinary: a config whose group public key or verification
// shares carry a small-subgroup (torsion) component — e.g. one produced by a
// poisoned keygen before the wire-level checks existed — must be rejected at
// load time instead of causing unidentifiable aborts at signing time.

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/MixinNetwork/multi-party-sig/common/params"
	"github.com/MixinNetwork/multi-party-sig/internal/test"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
)

const order8ConfigPointHex = "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"

func makeTestConfig(t *testing.T, group curve.Curve, public curve.Point, taintedShare party.ID) *Config {
	ids := test.PartyIDs(3)
	shares := make(map[party.ID]curve.Point, len(ids))
	for _, id := range ids {
		p := sample.Scalar(rand.Reader, group).ActOnBase()
		if id == taintedShare {
			tb, err := hex.DecodeString(order8ConfigPointHex)
			require.NoError(t, err)
			t8 := group.NewPoint()
			require.NoError(t, t8.UnmarshalBinary(tb))
			p = p.Add(t8)
		}
		shares[id] = p
	}
	if public == nil {
		public = sample.Scalar(rand.Reader, group).ActOnBase()
	}
	return &Config{
		ID:                 ids[0],
		Threshold:          2,
		PrivateShare:       sample.Scalar(rand.Reader, group),
		PublicKey:          public,
		ChainKey:           make([]byte, params.SecBytes),
		VerificationShares: party.NewPointMap(shares),
	}
}

func roundTripConfig(t *testing.T, cfg *Config) error {
	raw, err := cfg.MarshalBinary()
	require.NoError(t, err)
	back := EmptyConfig(cfg.Curve())
	return back.UnmarshalBinary(raw)
}

func TestConfigUnmarshalSubgroupChecks(t *testing.T) {
	group := curve.Edwards25519{}

	t.Run("valid config loads", func(t *testing.T) {
		require.NoError(t, roundTripConfig(t, makeTestConfig(t, group, nil, "")))
	})

	t.Run("torsion group public key rejected", func(t *testing.T) {
		tb, err := hex.DecodeString(order8ConfigPointHex)
		require.NoError(t, err)
		t8 := group.NewPoint()
		require.NoError(t, t8.UnmarshalBinary(tb))
		tainted := sample.Scalar(rand.Reader, group).ActOnBase().Add(t8)
		err = roundTripConfig(t, makeTestConfig(t, group, tainted, ""))
		assert.ErrorContains(t, err, "prime-order subgroup")
	})

	t.Run("identity group public key rejected", func(t *testing.T) {
		err := roundTripConfig(t, makeTestConfig(t, group, group.NewPoint(), ""))
		assert.ErrorContains(t, err, "identity point")
	})

	t.Run("torsion verification share rejected", func(t *testing.T) {
		victim := test.PartyIDs(3)[1]
		err := roundTripConfig(t, makeTestConfig(t, group, nil, victim))
		assert.ErrorContains(t, err, "prime-order subgroup")
	})
}
