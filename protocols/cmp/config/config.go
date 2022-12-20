package config

import (
	"io"
	"math"

	"github.com/MixinNetwork/multi-party-sig/common/types"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/polynomial"
	"github.com/MixinNetwork/multi-party-sig/pkg/paillier"
	"github.com/MixinNetwork/multi-party-sig/pkg/party"
	"github.com/MixinNetwork/multi-party-sig/pkg/pedersen"
)

// Config contains all necessary cryptographic keys necessary to generate a signature.
// It also represents the `SSID` after having performed a keygen/refresh operation.
// where SSID = (𝔾, t, n, P₁, …, Pₙ, (X₁, Y₁, N₁, s₁, t₁), …, (Xₙ, Yₙ, Nₙ, sₙ, tₙ)).
//
// To unmarshal this struct, EmptyConfig should be called first with a specific group,
// before using cbor.Unmarshal with that struct.
type Config struct {
	// Group returns the Elliptic Curve Group associated with this config.
	Group curve.Curve
	// ID is the identifier of the party this Config belongs to.
	ID party.ID
	// Threshold is the integer t which defines the maximum number of corruptions tolerated for this config.
	// Threshold + 1 is the minimum number of parties' shares required to reconstruct the secret/sign a message.
	Threshold int
	// ECDSA is this party's share xᵢ of the secret ECDSA x.
	ECDSA curve.Scalar
	// ElGamal is this party's yᵢ used for ElGamal.
	ElGamal curve.Scalar
	// Paillier is this party's Paillier decryption key.
	Paillier *paillier.SecretKey
	// RID is a 32 byte random identifier generated for this config
	RID types.RID
	// ChainKey is the chaining key value associated with this public key
	ChainKey types.RID
	// Public maps party.ID to public. It contains all public information associated to a party.
	Public map[party.ID]*Public
}

// Public holds public information for a party.
type Public struct {
	// ECDSA public key share
	ECDSA curve.Point
	// ElGamal is this party's public key for ElGamal encryption.
	ElGamal curve.Point
	// Paillier is this party's public Paillier key.
	Paillier *paillier.PublicKey
	// Pedersen is this party's public Pedersen parameters.
	Pedersen *pedersen.Parameters
}

// PublicPoint returns the group's public ECC point.
func (c *Config) PublicPoint() curve.Point {
	sum := c.Group.NewPoint()
	partyIDs := make([]party.ID, 0, len(c.Public))
	for j := range c.Public {
		partyIDs = append(partyIDs, j)
	}
	l := polynomial.Lagrange(c.Group, partyIDs)
	for j, partyJ := range c.Public {
		sum = sum.Add(l[j].Act(partyJ.ECDSA))
	}
	return sum
}

// PartyIDs returns a sorted slice of party IDs.
func (c *Config) PartyIDs() party.IDSlice {
	ids := make([]party.ID, 0, len(c.Public))
	for j := range c.Public {
		ids = append(ids, j)
	}
	return party.NewIDSlice(ids)
}

// WriteTo implements io.WriterTo interface.
func (c *Config) WriteTo(w io.Writer) (total int64, err error) {
	if c == nil {
		return 0, io.ErrUnexpectedEOF
	}
	var n int64

	// write t
	n, err = types.ThresholdWrapper(c.Threshold).WriteTo(w)
	total += n
	if err != nil {
		return
	}

	// write partyIDs
	partyIDs := c.PartyIDs()
	n, err = partyIDs.WriteTo(w)
	total += n
	if err != nil {
		return
	}

	// write rid
	n, err = c.RID.WriteTo(w)
	total += n
	if err != nil {
		return
	}

	// write all party data
	for _, j := range partyIDs {
		// write Xⱼ
		n, err = c.Public[j].WriteTo(w)
		total += n
		if err != nil {
			return
		}
	}
	return
}

// Domain implements hash.WriterToWithDomain.
func (c *Config) Domain() string {
	return "CMP Config"
}

// Domain implements hash.WriterToWithDomain.
func (Public) Domain() string {
	return "Public Data"
}

// WriteTo implements io.WriterTo interface.
func (p *Public) WriteTo(w io.Writer) (total int64, err error) {
	if p == nil {
		return 0, io.ErrUnexpectedEOF
	}
	// write ECDSA
	data, err := p.ECDSA.MarshalBinary()
	if err != nil {
		return
	}
	n, err := w.Write(data)
	total = int64(n)
	if err != nil {
		return
	}

	// write ElGamal
	data, err = p.ElGamal.MarshalBinary()
	if err != nil {
		return
	}
	n, err = w.Write(data)
	total += int64(n)
	if err != nil {
		return
	}

	n64, err := p.Paillier.WriteTo(w)
	total += n64
	if err != nil {
		return
	}

	n64, err = p.Pedersen.WriteTo(w)
	total += n64
	if err != nil {
		return
	}

	return
}

// CanSign returns true if the given _sorted_ list of signers is
// a valid subset of the original parties of size > t,
// and includes self.
func (c *Config) CanSign(signers party.IDSlice) bool {
	if !ValidThreshold(c.Threshold, len(signers)) {
		return false
	}

	// check for duplicates
	if !signers.Valid() {
		return false
	}

	if !signers.Contains(c.ID) {
		return false
	}

	// check that the signers are a subset of the original parties,
	// that it includes self, and that the size is > t.
	for _, j := range signers {
		if _, ok := c.Public[j]; !ok {
			return false
		}
	}

	return true
}

func ValidThreshold(t, n int) bool {
	if t < 0 || t > math.MaxUint32 {
		return false
	}
	if n <= 0 || t > n-1 {
		return false
	}
	return true
}
