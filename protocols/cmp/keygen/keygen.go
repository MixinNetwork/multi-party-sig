package keygen

import (
	"crypto/rand"
	"fmt"

	"github.com/MixinNetwork/multi-party-sig/common/round"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/polynomial"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/MixinNetwork/multi-party-sig/pkg/pool"
	"github.com/MixinNetwork/multi-party-sig/pkg/protocol"
)

const Rounds round.Number = 5

func Start(info round.Info, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (_ round.Session, err error) {
		helper, err := round.NewSession(info, sessionID, pl)
		if err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}

		group := helper.Group()

		// sample fᵢ(X) deg(fᵢ) = t, fᵢ(0) = secretᵢ
		VSSConstant := sample.Scalar(rand.Reader, group)
		VSSSecret := polynomial.NewPolynomial(group, helper.Threshold(), VSSConstant)
		return &round1{
			Helper:    helper,
			VSSSecret: VSSSecret,
		}, nil

	}
}
