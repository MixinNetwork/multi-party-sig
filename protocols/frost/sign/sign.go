package sign

import (
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
		info := round.Info{
			FinalRoundNumber: protocolRounds,
			SelfID:           result.ID,
			PartyIDs:         signers,
			Threshold:        result.Threshold,
			Group:            result.PublicKey.Curve(),
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
			err = r.mS.UnmarshalBinary(r.M[:32])
			if err != nil {
				panic(err)
			}
			r.M = r.M[34:]
		}

		return r, nil
	}
}
