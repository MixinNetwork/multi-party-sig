package sign

import (
	"bytes"
	"fmt"

	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/pkg/protocol"
	"github.com/MixinNetwork/multi-party-sig/protocols/frost/keygen"
)

const (
	ProtocolDefault       = 0
	ProtocolTaproot       = 1
	ProtocolEd25519SHA512 = 2
	ProtocolMixinPublic   = 3

	// Frost Sign with Threshold.
	protocolIDDefault       = "frost/sign-threshold-default"
	protocolIDTaproot       = "frost/sign-threshold-taproot"
	protocolIDEd25519SHA512 = "frost/sign-threshold-ed25519-sha512"
	protocolIDMixinPublic   = "frost/sign-threshold-mixin-public"
	// This protocol has 3 concrete rounds.
	protocolRounds round.Number = 3
)

func StartSignCommon(result *keygen.Config, signers []party.ID, messageHash []byte, protocol int) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		if result == nil || result.PublicKey == nil {
			return nil, fmt.Errorf("sign.StartSignCommon: missing group public key")
		}
		group := result.PublicKey.Curve()
		if group == nil {
			return nil, fmt.Errorf("sign.StartSignCommon: group public key has no curve")
		}
		if result.PrivateShare == nil {
			return nil, fmt.Errorf("sign.StartSignCommon: missing local private share")
		}
		privateGroup := result.PrivateShare.Curve()
		if privateGroup == nil {
			return nil, fmt.Errorf("sign.StartSignCommon: local private share has no curve")
		}
		if privateGroup.Name() != group.Name() {
			return nil, fmt.Errorf("sign.StartSignCommon: local private share has curve %s, expected %s", privateGroup.Name(), group.Name())
		}
		// The group public key is the root of trust for this signing session:
		// an identity key makes signatures trivially forgeable, and a point
		// outside the prime-order subgroup breaks the verification equation
		// on cofactored curves.
		if result.PublicKey.IsIdentity() {
			return nil, fmt.Errorf("sign.StartSignCommon: group public key is the identity point")
		}
		if !result.PublicKey.IsInPrimeOrderGroup() {
			return nil, fmt.Errorf("sign.StartSignCommon: group public key is not in the prime-order subgroup")
		}
		// Every signer needs a verification share: round 3 verifies each
		// signature share against it, and a missing entry would cause a nil
		// point dereference mid-protocol.
		if result.VerificationShares == nil {
			return nil, fmt.Errorf("sign.StartSignCommon: missing verification shares")
		}
		for _, id := range signers {
			v, ok := result.VerificationShares.Points[id]
			if !ok || v == nil {
				return nil, fmt.Errorf("sign.StartSignCommon: missing verification share for party %q", id)
			}
			verificationGroup := v.Curve()
			if verificationGroup == nil {
				return nil, fmt.Errorf("sign.StartSignCommon: verification share for party %q has no curve", id)
			}
			if verificationGroup.Name() != group.Name() {
				return nil, fmt.Errorf("sign.StartSignCommon: verification share for party %q has curve %s, expected %s", id, verificationGroup.Name(), group.Name())
			}
			if v.IsIdentity() {
				return nil, fmt.Errorf("sign.StartSignCommon: verification share for party %q is the identity point", id)
			}
			if !v.IsInPrimeOrderGroup() {
				return nil, fmt.Errorf("sign.StartSignCommon: verification share for party %q is not in the prime-order subgroup", id)
			}
		}
		info := round.Info{
			FinalRoundNumber: protocolRounds,
			SelfID:           result.ID,
			PartyIDs:         signers,
			Threshold:        result.Threshold,
			Group:            group,
		}
		switch protocol {
		case ProtocolTaproot:
			info.ProtocolID = protocolIDTaproot
			if result.Curve().Name() != (curve.Secp256k1{}).Name() {
				return nil, fmt.Errorf("sign.StartSignCommon: %s", result.Curve().Name())
			}
		case ProtocolEd25519SHA512:
			info.ProtocolID = protocolIDEd25519SHA512
			if result.Curve().Name() != (curve.Edwards25519{}).Name() {
				return nil, fmt.Errorf("sign.StartSignCommon: %s", result.Curve().Name())
			}
		case ProtocolMixinPublic:
			info.ProtocolID = protocolIDMixinPublic
			if result.Curve().Name() != (curve.Edwards25519{}).Name() {
				return nil, fmt.Errorf("sign.StartSignCommon: %s", result.Curve().Name())
			}
		case ProtocolDefault:
			info.ProtocolID = protocolIDDefault
		default:
			return nil, fmt.Errorf("sign.StartSignCommon: %d", protocol)
		}

		helper, err := round.NewSession(info, sessionID, nil)
		if err != nil {
			return nil, fmt.Errorf("sign.StartSign: %w", err)
		}
		// Reject a corrupted or mismatched local key share before round 1 creates
		// and broadcasts nonce commitments. Peers would eventually reject the
		// resulting signature share, but only after the whole session had started.
		localVerificationShare := result.VerificationShares.Points[result.ID]
		privateCommitment, err := result.PrivateShare.ActOnBase().MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("sign.StartSignCommon: encode local private share commitment: %w", err)
		}
		verificationCommitment, err := localVerificationShare.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("sign.StartSignCommon: encode local verification share: %w", err)
		}
		if !bytes.Equal(privateCommitment, verificationCommitment) {
			return nil, fmt.Errorf("sign.StartSignCommon: local private share does not match verification share for party %q", result.ID)
		}
		r := &round1{
			Helper:  helper,
			M:       messageHash,
			Y:       result.PublicKey,
			YShares: result.VerificationShares.Points,
			s_i:     result.PrivateShare,
		}

		if protocol == ProtocolMixinPublic {
			if len(r.M) < 32 {
				return nil, fmt.Errorf("sign.StartSignCommon: %d", len(r.M))
			}
			r.mS = result.Curve().NewScalar()
			if err = r.mS.UnmarshalBinary(r.M[:32]); err != nil {
				return nil, fmt.Errorf("sign.StartSignCommon: invalid mixin scalar: %w", err)
			}
			r.M = r.M[32:]
		}

		return r, nil
	}
}
