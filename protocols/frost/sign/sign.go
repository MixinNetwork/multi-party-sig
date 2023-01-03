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
	ProtocolDefault = 0
	ProtocolTaproot = 1
	ProtocolMixin   = 2

	// Frost Sign with Threshold.
	protocolID        = "frost/sign-threshold"
	protocolIDTaproot = "frost/sign-threshold-taproot"
	protocolIDMixin   = "frost/sign-threshold-mixin"
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
		case ProtocolMixin:
			info.ProtocolID = protocolIDMixin
			if result.Curve().Name() != (curve.Edwards25519{}).Name() {
				return nil, fmt.Errorf("sign.StartSignCommon: %s", result.Curve().Name())
			}
		case ProtocolDefault:
			info.ProtocolID = protocolID
		default:
			return nil, fmt.Errorf("sign.StartSignCommon: %d", protocol)
		}

		helper, err := round.NewSession(info, sessionID, nil)
		if err != nil {
			return nil, fmt.Errorf("sign.StartSign: %w", err)
		}
		return &round1{
			Helper:  helper,
			M:       messageHash,
			Y:       result.PublicKey,
			YShares: result.VerificationShares.Points,
			s_i:     result.PrivateShare,
		}, nil
	}
}
