package keygen

import (
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/pkg/taproot"
)

// Config contains all the information produced after key generation, from the perspective
// of a single participant.
//
// When unmarshalling, EmptyResult needs to be called to set the group, before
// calling cbor.Unmarshal, or equivalent methods.
type Config struct {
	// ID is the identifier for this participant.
	ID party.ID
	// Threshold is the number of accepted corruptions while still being able to sign.
	Threshold int
	// PrivateShare is the fraction of the secret key owned by this participant.
	PrivateShare curve.Scalar
	// PublicKey is the shared public key for this consortium of signers.
	//
	// This key can be used to verify signatures produced by the consortium.
	PublicKey curve.Point
	// ChainKey is the additional randomness we've agreed upon.
	//
	// This is only ever useful if you do BIP-32 key derivation, or something similar.
	ChainKey []byte
	// VerificationShares is a map between parties and a commitment to their private share.
	//
	// This will later be used to verify the integrity of the signing protocol.
	VerificationShares *party.PointMap
}

// EmptyConfig creates an empty Result with a specific group.
//
// This needs to be called before unmarshalling, instead of just using new(Result).
// This is to allow points and scalars to be correctly unmarshalled.
func EmptyConfig(group curve.Curve) *Config {
	return &Config{
		PrivateShare:       group.NewScalar(),
		PublicKey:          group.NewPoint(),
		VerificationShares: party.EmptyPointMap(group),
	}
}

// Curve returns the Elliptic Curve Group associated with this result.
func (r *Config) Curve() curve.Curve {
	return r.PublicKey.Curve()
}

// TaprootConfig is like result, but for Taproot / BIP-340 keys.
//
// The main difference is that our public key is an actual taproot public key.
type TaprootConfig struct {
	// ID is the identifier for this participant.
	ID party.ID
	// Threshold is the number of accepted corruptions while still being able to sign.
	Threshold int
	// PrivateShare is the fraction of the secret key owned by this participant.
	PrivateShare *curve.Secp256k1Scalar
	// PublicKey is the shared public key for this consortium of signers.
	//
	// This key can be used to verify signatures produced by the consortium.
	PublicKey taproot.PublicKey
	// ChainKey is the additional randomness we've agreed upon.
	//
	// This is only ever useful if you do BIP-32 key derivation, or something similar.
	ChainKey []byte
	// VerificationShares is a map between parties and a commitment to their private share.
	//
	// This will later be used to verify the integrity of the signing protocol.
	VerificationShares map[party.ID]*curve.Secp256k1Point
}

// Clone creates a deep clone of this struct, and all the values contained inside
func (r *TaprootConfig) Clone() *TaprootConfig {
	publicKeyCopy := make([]byte, len(r.PublicKey))
	copy(publicKeyCopy, r.PublicKey)
	chainKeyCopy := make([]byte, len(r.ChainKey))
	copy(chainKeyCopy, r.ChainKey)
	verificationSharesCopy := make(map[party.ID]*curve.Secp256k1Point)
	for k, v := range r.VerificationShares {
		verificationSharesCopy[k] = v
	}
	return &TaprootConfig{
		ID:                 r.ID,
		Threshold:          r.Threshold,
		PrivateShare:       curve.Secp256k1{}.NewScalar().Set(r.PrivateShare).(*curve.Secp256k1Scalar),
		PublicKey:          publicKeyCopy,
		ChainKey:           chainKeyCopy,
		VerificationShares: verificationSharesCopy,
	}
}
