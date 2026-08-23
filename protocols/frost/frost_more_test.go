package frost

import (
	"testing"

	"github.com/MixinNetwork/multi-party-sig/internal/test"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost/sign"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmptyConfig(t *testing.T) {
	for _, group := range []curve.Curve{curve.Secp256k1{}, curve.Edwards25519{}} {
		c := EmptyConfig(group)
		require.NotNil(t, c)
		assert.True(t, c.PublicKey.IsIdentity())
		assert.True(t, c.PrivateShare.IsZero())
		assert.NotNil(t, c.VerificationShares)
		assert.Empty(t, c.VerificationShares.Points)
		assert.Equal(t, group.Name(), c.Curve().Name())
	}
}

func TestSignTaproot_InvalidPublicKey(t *testing.T) {
	// an invalid taproot public key (x not on curve) must produce a StartFunc
	// that fails immediately
	bad := &TaprootConfig{
		PublicKey: make([]byte, 32),
	}
	bad.PublicKey[31] = 5 // x = 5 is not on the curve
	_, err := SignTaproot(bad, []party.ID{"a"}, []byte("m"))(test.SessionID("bad-taproot"))
	assert.Error(t, err)
}

func TestSignTaproot_LocalPrivateShareMismatch(t *testing.T) {
	group := curve.Secp256k1{}
	verificationScalar := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1))
	publicKey := verificationScalar.ActOnBase()
	config := &TaprootConfig{
		ID:           "a",
		Threshold:    0,
		PrivateShare: group.NewScalar().SetNat(new(saferith.Nat).SetUint64(2)),
		PublicKey:    publicKey.XScalar().Bytes(),
		VerificationShares: map[party.ID]curve.Point{
			"a": publicKey,
		},
	}
	_, err := SignTaproot(config, []party.ID{"a"}, []byte("message"))(test.SessionID("taproot-share-mismatch"))
	assert.ErrorContains(t, err, "local private share does not match verification share")
}

func TestSign_UnknownVariant(t *testing.T) {
	group := curve.Secp256k1{}
	config := EmptyConfig(group)
	config.ID = "a"
	// an unknown variant must fail on start
	_, err := Sign(config, []party.ID{"a", "b"}, []byte("m"), 42)(test.SessionID("bad-variant"))
	assert.Error(t, err)
}

func TestSign_TaprootVariantOnEdwards(t *testing.T) {
	group := curve.Edwards25519{}
	config := EmptyConfig(group)
	config.ID = "a"
	// taproot signing requires secp256k1
	_, err := Sign(config, []party.ID{"a", "b"}, []byte("m"), sign.ProtocolTaproot)(test.SessionID("tap-edwards"))
	assert.Error(t, err)
	// ed25519 signing requires edwards25519
	configSecp := EmptyConfig(curve.Secp256k1{})
	configSecp.ID = "a"
	_, err = Sign(configSecp, []party.ID{"a", "b"}, []byte("m"), sign.ProtocolEd25519SHA512)(test.SessionID("ed-secp"))
	assert.Error(t, err)
}
