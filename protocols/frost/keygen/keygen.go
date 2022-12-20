package keygen

import (
	"fmt"

	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/pkg/protocol"
)

const (
	// Frost KeyGen with Threshold.
	protocolID        = "frost/keygen-threshold"
	protocolIDTaproot = "frost/keygen-threshold-taproot"
	// This protocol has 3 concrete rounds.
	protocolRounds round.Number = 3
)

// These assert that our rounds implement the round.Round interface.
var (
	_ round.Round = (*round1)(nil)
	_ round.Round = (*round2)(nil)
	_ round.Round = (*round3)(nil)
)

func StartKeygenCommon(taproot bool, group curve.Curve, participants []party.ID, threshold int, selfID party.ID) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		info := round.Info{
			FinalRoundNumber: protocolRounds,
			SelfID:           selfID,
			PartyIDs:         participants,
			Threshold:        threshold,
			Group:            group,
		}
		if taproot {
			info.ProtocolID = protocolIDTaproot
		} else {
			info.ProtocolID = protocolID
		}

		helper, err := round.NewSession(info, sessionID, nil)
		if err != nil {
			return nil, fmt.Errorf("keygen.StartKeygen: %w", err)
		}

		privateShare := group.NewScalar()
		publicKey := group.NewPoint()
		verificationShares := make(map[party.ID]curve.Point, len(participants))
		for _, k := range participants {
			verificationShares[k] = group.NewPoint()
		}

		return &round1{
			Helper:             helper,
			taproot:            taproot,
			threshold:          threshold,
			privateShare:       privateShare,
			verificationShares: verificationShares,
			publicKey:          publicKey,
		}, nil
	}
}
