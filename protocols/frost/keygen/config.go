package keygen

import (
	"bytes"
	"fmt"

	"github.com/MixinNetwork/mixin/common"
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

func (r *Config) PublicPoint() curve.Point {
	return r.PublicKey
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
	PrivateShare curve.Scalar
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
	VerificationShares map[party.ID]curve.Point
}

// Clone creates a deep clone of this struct, and all the values contained inside
func (r *TaprootConfig) Clone() *TaprootConfig {
	publicKeyCopy := make([]byte, len(r.PublicKey))
	copy(publicKeyCopy, r.PublicKey)
	chainKeyCopy := make([]byte, len(r.ChainKey))
	copy(chainKeyCopy, r.ChainKey)
	verificationSharesCopy := make(map[party.ID]curve.Point)
	for k, v := range r.VerificationShares {
		verificationSharesCopy[k] = v
	}
	return &TaprootConfig{
		ID:                 r.ID,
		Threshold:          r.Threshold,
		PrivateShare:       curve.Secp256k1{}.NewScalar().Set(r.PrivateShare),
		PublicKey:          publicKeyCopy,
		ChainKey:           chainKeyCopy,
		VerificationShares: verificationSharesCopy,
	}
}

func (c *Config) MarshalBinary() ([]byte, error) {
	enc := common.NewEncoder()
	switch c.Curve().Name() {
	case (curve.Secp256k1{}).Name():
		enc.WriteInt(0)
	case (curve.Edwards25519{}).Name():
		enc.WriteInt(1)
	default:
		return nil, fmt.Errorf("curve %s", c.Curve().Name())
	}

	writeBytes(enc, []byte(c.ID))
	enc.WriteInt(c.Threshold)

	b, err := c.PrivateShare.MarshalBinary()
	if err != nil {
		panic(err)
	}
	writeBytes(enc, b)

	b, err = c.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	writeBytes(enc, b)

	writeBytes(enc, c.ChainKey)
	b, err = c.VerificationShares.MarshalBinary()
	if err != nil {
		panic(err)
	}
	writeBytes(enc, b)

	return enc.Bytes(), nil
}

func (c *Config) UnmarshalBinary(data []byte) error {
	dec := common.NewDecoder(data)
	crv, err := dec.ReadInt()
	if err != nil {
		return fmt.Errorf("curve error %v", err)
	}
	var group curve.Curve
	switch crv {
	case 0:
		group = curve.Secp256k1{}
	case 1:
		group = curve.Edwards25519{}
	default:
		return fmt.Errorf("curve invalid %d", crv)
	}
	if c.Curve().Name() != group.Name() {
		return fmt.Errorf("curve invalid %s %s", c.Curve().Name(), group.Name())
	}

	id, err := dec.ReadBytes()
	if err != nil {
		return fmt.Errorf("id error %v", err)
	}
	c.ID = party.ID(id)

	threshold, err := dec.ReadInt()
	if err != nil {
		return fmt.Errorf("threshold error %v", err)
	}
	c.Threshold = threshold

	share, err := dec.ReadBytes()
	if err != nil {
		return fmt.Errorf("private share error %v", err)
	}
	err = c.PrivateShare.UnmarshalBinary(share)
	if err != nil {
		return fmt.Errorf("private share error %v", err)
	}

	public, err := dec.ReadBytes()
	if err != nil {
		return fmt.Errorf("public key error %v", err)
	}
	err = c.PublicKey.UnmarshalBinary(public)
	if err != nil {
		return fmt.Errorf("public key error %v", err)
	}

	ck, err := dec.ReadBytes()
	if err != nil {
		return fmt.Errorf("chain key error %v", err)
	}
	c.ChainKey = ck

	pm, err := dec.ReadBytes()
	if err != nil {
		return fmt.Errorf("point map error %v", err)
	}
	err = c.VerificationShares.UnmarshalBinary(pm)
	if err != nil {
		return fmt.Errorf("point map error %v", err)
	}

	check, err := c.MarshalBinary()
	if err != nil || !bytes.Equal(data, check) {
		return fmt.Errorf("check failed %v %x %x", err, data, check)
	}
	return nil
}

func writeBytes(enc *common.Encoder, b []byte) {
	enc.WriteInt(len(b))
	enc.Write(b)
}
