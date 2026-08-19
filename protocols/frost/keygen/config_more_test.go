package keygen

import (
	"crypto/rand"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/common/params"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/polynomial"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/pkg/taproot"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testConfigs(t *testing.T, group curve.Curve, n int) ([]*Config, []party.ID) {
	t.Helper()
	partyIDs := make([]party.ID, n)
	for i := range partyIDs {
		partyIDs[i] = party.ID(string(rune('a' + i)))
	}
	secret := sample.Scalar(rand.Reader, group)
	f := polynomial.NewPolynomial(group, 1, secret)

	// the chain key is shared between all parties
	chainKey := make([]byte, params.SecBytes)
	_, err := rand.Read(chainKey)
	require.NoError(t, err)

	configs := make([]*Config, n)
	for i, id := range partyIDs {
		verificationShares := make(map[party.ID]curve.Point)
		for _, j := range partyIDs {
			verificationShares[j] = f.Evaluate(j.Scalar(group)).ActOnBase()
		}
		configs[i] = &Config{
			ID:                 id,
			Threshold:          1,
			PrivateShare:       f.Evaluate(id.Scalar(group)),
			PublicKey:          secret.ActOnBase(),
			ChainKey:           chainKey,
			VerificationShares: party.NewPointMap(verificationShares),
		}
	}
	return configs, partyIDs
}

func TestConfig_PublicPointAndCurve(t *testing.T) {
	group := curve.Secp256k1{}
	configs, _ := testConfigs(t, group, 3)
	assert.Equal(t, "secp256k1", configs[0].Curve().Name())
	assert.True(t, configs[0].PublicPoint().Equal(configs[0].PublicKey))
}

func TestConfig_Derive(t *testing.T) {
	group := curve.Secp256k1{}
	configs, _ := testConfigs(t, group, 3)

	adjust := sample.Scalar(rand.Reader, group)
	newChainKey := make([]byte, params.SecBytes)
	_, err := rand.Read(newChainKey)
	require.NoError(t, err)

	derived, err := configs[0].Derive(adjust, newChainKey)
	require.NoError(t, err)

	// the public key must be adjusted
	assert.True(t, derived.PublicKey.Equal(configs[0].PublicKey.Add(adjust.ActOnBase())))
	// the private share must be adjusted
	assert.True(t, derived.PrivateShare.Equal(
		group.NewScalar().Set(configs[0].PrivateShare).Add(adjust)))
	// the chain key must be the new one
	assert.Equal(t, newChainKey, derived.ChainKey)

	// deriving with no new chain key keeps the old one
	derived2, err := configs[0].Derive(adjust, nil)
	require.NoError(t, err)
	assert.Equal(t, configs[0].ChainKey, derived2.ChainKey)

	// deriving with a zero adjust is a no-op
	zero := group.NewScalar()
	derived3, err := configs[0].Derive(zero, nil)
	require.NoError(t, err)
	assert.True(t, derived3.PublicKey.Equal(configs[0].PublicKey))

	// a wrong-length chain key must error
	_, err = configs[0].Derive(adjust, []byte{1, 2, 3})
	assert.Error(t, err)
}

func TestConfig_DeriveChild(t *testing.T) {
	group := curve.Secp256k1{}
	configs, _ := testConfigs(t, group, 3)

	child, err := configs[0].DeriveChild(5)
	require.NoError(t, err)
	require.NotNil(t, child)

	// all parties derive the same child public key and chain key
	for i := 1; i < len(configs); i++ {
		childI, err := configs[i].DeriveChild(5)
		require.NoError(t, err)
		assert.True(t, child.PublicKey.Equal(childI.PublicKey), "child public keys must match")
		assert.Equal(t, child.ChainKey, childI.ChainKey, "child chain keys must match")
	}

	// a different index yields a different key
	other, err := configs[0].DeriveChild(6)
	require.NoError(t, err)
	assert.False(t, child.PublicKey.Equal(other.PublicKey))
}

func TestConfig_DeriveChildEdwardsFails(t *testing.T) {
	group := curve.Edwards25519{}
	configs, _ := testConfigs(t, group, 2)
	_, err := configs[0].DeriveChild(0)
	assert.Error(t, err, "DeriveChild must fail on non secp256k1 curves")
}

func TestTaprootConfig_Clone(t *testing.T) {
	group := curve.Secp256k1{}
	configs, _ := testConfigs(t, group, 3)
	c := configs[0]

	// build a TaprootConfig from the regular config
	verificationShares := make(map[party.ID]curve.Point)
	for id, v := range c.VerificationShares.Points {
		verificationShares[id] = v
	}
	pub := c.PublicKey.(*curve.Secp256k1Point)
	tap := &TaprootConfig{
		ID:                 c.ID,
		Threshold:          c.Threshold,
		PrivateShare:       c.PrivateShare,
		PublicKey:          taproot.PublicKey(pub.XScalar().Bytes()),
		ChainKey:           c.ChainKey,
		VerificationShares: verificationShares,
	}

	cloned := tap.Clone()
	assert.Equal(t, tap.ID, cloned.ID)
	assert.Equal(t, tap.Threshold, cloned.Threshold)
	assert.True(t, tap.PrivateShare.Equal(cloned.PrivateShare))
	assert.Equal(t, tap.PublicKey, cloned.PublicKey)
	assert.Equal(t, tap.ChainKey, cloned.ChainKey)
	assert.Equal(t, tap.VerificationShares, cloned.VerificationShares)

	// the clone must be independent
	cloned.PrivateShare.Add(group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1)))
	assert.True(t, tap.PrivateShare.Equal(cloned.PrivateShare) == false)
}

func TestTaprootConfig_MarshalRoundTrip(t *testing.T) {
	group := curve.Secp256k1{}
	configs, _ := testConfigs(t, group, 3)
	c := configs[0]

	verificationShares := make(map[party.ID]curve.Point)
	for id, v := range c.VerificationShares.Points {
		verificationShares[id] = v
	}
	pub := c.PublicKey.(*curve.Secp256k1Point)
	tap := &TaprootConfig{
		ID:                 c.ID,
		Threshold:          c.Threshold,
		PrivateShare:       c.PrivateShare,
		PublicKey:          taproot.PublicKey(pub.XScalar().Bytes()),
		ChainKey:           c.ChainKey,
		VerificationShares: verificationShares,
	}

	data, err := tap.MarshalBinary()
	require.NoError(t, err)

	unmarshalled := &TaprootConfig{
		PrivateShare: group.NewScalar(),
	}
	require.NoError(t, unmarshalled.UnmarshalBinary(data))
	assert.Equal(t, tap.ID, unmarshalled.ID)
	assert.Equal(t, tap.Threshold, unmarshalled.Threshold)
	assert.True(t, tap.PrivateShare.Equal(unmarshalled.PrivateShare))
	assert.Equal(t, tap.PublicKey, unmarshalled.PublicKey)
	assert.Equal(t, tap.ChainKey, unmarshalled.ChainKey)
	for id, p := range tap.VerificationShares {
		assert.True(t, unmarshalled.VerificationShares[id].Equal(p))
	}

	// corrupted data must fail
	assert.Error(t, unmarshalled.UnmarshalBinary([]byte{0xff}))
	assert.Error(t, unmarshalled.UnmarshalBinary(nil))
}

func TestTaprootConfig_Derive(t *testing.T) {
	group := curve.Secp256k1{}
	configs, _ := testConfigs(t, group, 3)
	c := configs[0]

	verificationShares := make(map[party.ID]curve.Point)
	for id, v := range c.VerificationShares.Points {
		verificationShares[id] = v
	}
	pub := c.PublicKey.(*curve.Secp256k1Point)
	tap := &TaprootConfig{
		ID:                 c.ID,
		Threshold:          c.Threshold,
		PrivateShare:       c.PrivateShare.(*curve.Secp256k1Scalar),
		PublicKey:          taproot.PublicKey(pub.XScalar().Bytes()),
		ChainKey:           c.ChainKey,
		VerificationShares: verificationShares,
	}

	adjust := sample.Scalar(rand.Reader, group).(*curve.Secp256k1Scalar)
	derived, err := tap.Derive(adjust, nil)
	require.NoError(t, err)
	require.NotNil(t, derived)

	// the derived public key must be the x coordinate of the adjusted point;
	// Derive normalizes the base key to its even-Y representation first
	base, err := curve.Secp256k1{}.LiftX(tap.PublicKey)
	require.NoError(t, err)
	expectedPub := base.Add(adjust.ActOnBase())
	assert.Equal(t, taproot.PublicKey(expectedPub.XScalar().Bytes()), derived.PublicKey)

	// wrong chain key length must error
	_, err = tap.Derive(adjust, []byte{1})
	assert.Error(t, err)
}

func TestConfig_MarshalCorruption(t *testing.T) {
	group := curve.Secp256k1{}
	configs, _ := testConfigs(t, group, 3)
	c := configs[0]

	data, err := c.MarshalBinary()
	require.NoError(t, err)

	// truncations at every offset must be rejected
	for i := 0; i < len(data); i += 7 {
		corrupt := data[:i]
		cfg := EmptyConfig(group)
		if err := cfg.UnmarshalBinary(corrupt); err == nil {
			t.Fatalf("truncated config at %d accepted", i)
		}
	}

	// trailing garbage must be rejected (round-trip check)
	cfg := EmptyConfig(group)
	assert.Error(t, cfg.UnmarshalBinary(append(data, 0x00)))
}

func TestTaprootConfig_MarshalCorruption(t *testing.T) {
	group := curve.Secp256k1{}
	configs, _ := testConfigs(t, group, 3)
	c := configs[0]
	verificationShares := make(map[party.ID]curve.Point)
	for id, v := range c.VerificationShares.Points {
		verificationShares[id] = v
	}
	pub := c.PublicKey.(*curve.Secp256k1Point)
	tap := &TaprootConfig{
		ID:                 c.ID,
		Threshold:          c.Threshold,
		PrivateShare:       c.PrivateShare.(*curve.Secp256k1Scalar),
		PublicKey:          taproot.PublicKey(pub.XScalar().Bytes()),
		ChainKey:           c.ChainKey,
		VerificationShares: verificationShares,
	}

	data, err := tap.MarshalBinary()
	require.NoError(t, err)

	for i := 1; i < len(data); i *= 2 {
		unmarshalled := &TaprootConfig{PrivateShare: group.NewScalar()}
		if err := unmarshalled.UnmarshalBinary(data[:i]); err == nil {
			t.Fatalf("truncated taproot config at %d accepted", i)
		}
	}
}

func TestTaprootConfig_DeriveChild(t *testing.T) {
	group := curve.Secp256k1{}
	configs, _ := testConfigs(t, group, 3)
	c := configs[0]

	verificationShares := make(map[party.ID]curve.Point)
	for id, v := range c.VerificationShares.Points {
		verificationShares[id] = v
	}
	pub := c.PublicKey.(*curve.Secp256k1Point)
	tap := &TaprootConfig{
		ID:                 c.ID,
		Threshold:          c.Threshold,
		PrivateShare:       c.PrivateShare.(*curve.Secp256k1Scalar),
		PublicKey:          taproot.PublicKey(pub.XScalar().Bytes()),
		ChainKey:           c.ChainKey,
		VerificationShares: verificationShares,
	}

	// a hardened index must panic
	assert.Panics(t, func() {
		_, _ = tap.DeriveChild(1 << 31)
	})

	// an invalid public key (x not on curve) must error cleanly
	badTap := &TaprootConfig{
		ID:                 c.ID,
		Threshold:          c.Threshold,
		PrivateShare:       c.PrivateShare.(*curve.Secp256k1Scalar),
		PublicKey:          taproot.PublicKey{0, 0, 0, 5},
		ChainKey:           c.ChainKey,
		VerificationShares: verificationShares,
	}
	_, err := badTap.DeriveChild(0)
	assert.Error(t, err)

	child, err := tap.DeriveChild(1)
	require.NoError(t, err)
	require.NotNil(t, child)

	for i := 1; i < len(configs); i++ {
		ci := configs[i]
		vs := make(map[party.ID]curve.Point)
		for id, v := range ci.VerificationShares.Points {
			vs[id] = v
		}
		pubI := ci.PublicKey.(*curve.Secp256k1Point)
		tapI := &TaprootConfig{
			ID:                 ci.ID,
			Threshold:          ci.Threshold,
			PrivateShare:       ci.PrivateShare.(*curve.Secp256k1Scalar),
			PublicKey:          taproot.PublicKey(pubI.XScalar().Bytes()),
			ChainKey:           ci.ChainKey,
			VerificationShares: vs,
		}
		childI, err := tapI.DeriveChild(1)
		require.NoError(t, err)
		assert.Equal(t, child.PublicKey, childI.PublicKey)
		assert.Equal(t, child.ChainKey, childI.ChainKey)
	}
}
