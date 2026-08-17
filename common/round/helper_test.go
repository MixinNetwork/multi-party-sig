package round_test

import (
	"math/big"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/internal/test"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
)

func TestNewSession(t *testing.T) {
	RNumber := round.Number(5)
	T := 20
	N := 26
	partyIDs := test.PartyIDs(N)
	selfID := partyIDs[0]
	tests := []struct {
		name        string
		roundNumber round.Number
		selfID      party.ID
		partyIDs    []party.ID
		threshold   int
		group       curve.Curve
		wantErr     bool
	}{
		{
			"-1 t",
			RNumber,
			selfID,
			partyIDs,
			-1,
			curve.Secp256k1{},
			true,
		},
		{
			"invalid selfID",
			RNumber,
			"",
			partyIDs,
			T,
			curve.Secp256k1{},
			true,
		},
		{
			"duplicate selfID",
			RNumber,
			selfID,
			append(partyIDs, selfID),
			T,
			curve.Secp256k1{},
			true,
		},
		{
			"duplicate second ID",
			RNumber,
			selfID,
			append(partyIDs, partyIDs[1]),
			T,
			curve.Secp256k1{},
			true,
		},
		{
			"duplicate partyIDs",
			RNumber,
			selfID,
			append(partyIDs, partyIDs...),
			T,
			curve.Secp256k1{},
			true,
		},
		{
			"threshold N",
			RNumber,
			selfID,
			partyIDs,
			N,
			curve.Secp256k1{},
			true,
		},
		{
			"threshold T with T parties",
			RNumber,
			selfID,
			partyIDs[:T],
			T,
			curve.Secp256k1{},
			true,
		},
		{
			"no group",
			RNumber,
			selfID,
			partyIDs,
			T,
			curve.Secp256k1{},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := round.Info{
				ProtocolID:       "TEST",
				FinalRoundNumber: tt.roundNumber,
				SelfID:           tt.selfID,
				PartyIDs:         tt.partyIDs,
				Threshold:        tt.threshold,
				Group:            tt.group,
			}
			_, err := round.NewSession(info, test.SessionID(tt.name), nil)
			if tt.wantErr == (err == nil) {
				t.Error(err)
			}
		})
	}

	t.Run("invalid session id", func(t *testing.T) {
		info := round.Info{
			ProtocolID:       "TEST",
			FinalRoundNumber: RNumber,
			SelfID:           selfID,
			PartyIDs:         partyIDs,
			Threshold:        T,
			Group:            curve.Secp256k1{},
		}
		_, err := round.NewSession(info, nil, nil)
		if err == nil {
			t.Fatal("expected invalid session ID error")
		}
	})
}

func TestNewSessionIDScalars(t *testing.T) {
	group := curve.Secp256k1{}
	q := group.Order().Nat().Big()

	// id1 = q maps to the zero scalar; id2 = 42 and id3 = 42 + q collide
	zeroID := party.ID(string(q.Bytes()))
	id2 := party.ID(string(big.NewInt(42).Bytes()))
	id3 := party.ID(string(new(big.Int).Add(big.NewInt(42), q).Bytes()))

	tests := []struct {
		name     string
		selfID   party.ID
		partyIDs []party.ID
		wantErr  bool
	}{
		{"zero scalar ID", "a", []party.ID{"a", zeroID, "c"}, true},
		{"empty ID", "a", []party.ID{"a", "", "c"}, true},
		{"colliding IDs", "a", []party.ID{"a", id2, id3}, true},
		{"colliding IDs incl. self", id2, []party.ID{id2, id3, "c"}, true},
		{"valid IDs", "a", []party.ID{"a", "b", "c"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := round.Info{
				ProtocolID:       "TEST",
				FinalRoundNumber: round.Number(5),
				SelfID:           tt.selfID,
				PartyIDs:         tt.partyIDs,
				Threshold:        1,
				Group:            group,
			}
			_, err := round.NewSession(info, test.SessionID(tt.name), nil)
			if tt.wantErr == (err == nil) {
				t.Error(err)
			}
		})
	}
}
