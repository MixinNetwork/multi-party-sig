package paillier

import (
	"bytes"
	"crypto/rand"
	"io"
	"math/big"
	"testing"

	"github.com/MixinNetwork/multi-party-sig/pkg/math/sample"
	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCiphertext_AddMulNil(t *testing.T) {
	m := new(saferith.Int).SetUint64(42)
	ct, _ := paillierPublic.Enc(m)
	orig := ct.Clone()

	// nil arguments must be no-ops
	assert.Equal(t, ct, ct.Add(paillierPublic, nil))
	assert.Equal(t, ct, ct.Mul(paillierPublic, nil))
	assert.True(t, ct.Equal(orig))
}

func TestCiphertext_Randomize(t *testing.T) {
	m := new(saferith.Int).SetUint64(123)
	ct, _ := paillierPublic.Enc(m)
	orig := ct.Clone()

	// randomization preserves the plaintext
	nonce := ct.Randomize(paillierPublic, nil)
	require.NotNil(t, nonce)
	dec, err := paillierSecret.Dec(ct)
	require.NoError(t, err)
	assert.True(t, m.Eq(dec) == 1)
	assert.False(t, ct.Equal(orig))

	// explicit nonce
	ct2, _ := paillierPublic.Enc(m)
	explicit := sample.UnitModN(rand.Reader, paillierPublic.n.Modulus)
	returned := ct2.Randomize(paillierPublic, explicit)
	assert.Equal(t, explicit, returned)
	dec2, err := paillierSecret.Dec(ct2)
	require.NoError(t, err)
	assert.True(t, m.Eq(dec2) == 1)
}

func TestCiphertext_WriteTo(t *testing.T) {
	ct, _ := paillierPublic.Enc(new(saferith.Int).SetUint64(5))
	var buf bytes.Buffer
	n, err := ct.WriteTo(&buf)
	require.NoError(t, err)
	assert.Equal(t, int64(len(buf.Bytes())), n)
	// a ciphertext occupies N², i.e. 512 bytes, when canonically padded
	assert.Len(t, buf.Bytes(), 512)

	var nilCt *Ciphertext
	_, err = nilCt.WriteTo(&buf)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)

	assert.Equal(t, "Paillier Ciphertext", ct.Domain())
}

func TestCiphertext_Nat(t *testing.T) {
	ct, _ := paillierPublic.Enc(new(saferith.Int).SetUint64(5))
	nat := ct.Nat()
	require.NotNil(t, nat)
	assert.True(t, nat.Eq(ct.c) == 1)
	// the result must be a copy
	nat.SetUint64(1)
	assert.False(t, nat.Eq(ct.c) == 1)
}

func TestSecretKey_Accessors(t *testing.T) {
	assert.NotNil(t, paillierSecret.P())
	assert.NotNil(t, paillierSecret.Q())
	assert.NotNil(t, paillierSecret.Phi())
	assert.NotEqual(t, paillierSecret.P(), paillierSecret.Q())

	// phi must equal (p-1)(q-1)
	pMinus1 := new(big.Int).Sub(paillierSecret.P().Big(), big.NewInt(1))
	qMinus1 := new(big.Int).Sub(paillierSecret.Q().Big(), big.NewInt(1))
	expectedPhi := pMinus1.Mul(pMinus1, qMinus1)
	assert.Equal(t, 0, paillierSecret.Phi().Big().Cmp(expectedPhi))
}

func TestSecretKey_GeneratePedersen(t *testing.T) {
	ped, lambda := paillierSecret.GeneratePedersen()
	require.NotNil(t, ped)
	require.NotNil(t, lambda)

	// s must equal t^lambda mod N
	tParam := ped.T()
	expected := new(saferith.Nat).Exp(tParam, lambda, paillierPublic.n.Modulus)
	assert.Equal(t, expected.Eq(ped.S()) == 1, true, "s != t^lambda")
}

func TestValidatePrime_Errors(t *testing.T) {
	// nil is rejected
	assert.ErrorIs(t, ValidatePrime(nil), ErrPrimeNil)

	// wrong size (a small safe prime)
	small := new(saferith.Nat).SetUint64(11)
	assert.ErrorIs(t, ValidatePrime(small), ErrPrimeBadLength)

	// right size, but even (p - 1 keeps the bit length whp)
	one := new(saferith.Nat).SetUint64(1)
	even := new(saferith.Nat).Sub(paillierSecret.P(), one, -1)
	err := ValidatePrime(even)
	assert.Error(t, err, "even value accepted")

	// right size, ≡ 1 (mod 4) (p + 2 flips the low bits to ...01)
	two := new(saferith.Nat).SetUint64(2)
	nonBlum := new(saferith.Nat).Add(paillierSecret.P(), two, -1)
	if nonBlum.TrueLen() == 1024 {
		err = ValidatePrime(nonBlum)
		assert.ErrorIs(t, err, ErrNotBlum, "non-Blum value accepted")
	}

	// a 1024-bit prime ≡ 3 mod 4 whose (p-1)/2 is not prime
	pBig := paillierSecret.P().Big()
	candidate := new(big.Int).Add(pBig, big.NewInt(4))
	for i := 0; i < 20000 && candidate.BitLen() == 1024; i++ {
		if candidate.Bit(0) == 1 && candidate.Bit(1) == 1 && candidate.ProbablyPrime(20) {
			half := new(big.Int).Rsh(candidate, 1)
			if !half.ProbablyPrime(20) {
				cNat := new(saferith.Nat).SetBig(candidate, candidate.BitLen())
				err := ValidatePrime(cNat)
				assert.ErrorIs(t, err, ErrNotSafePrime, "non-safe prime accepted")
				return
			}
		}
		candidate.Add(candidate, big.NewInt(4))
	}
	t.Log("no non-safe prime found in the search window; skipping that case")
}

func TestValidateN_Errors(t *testing.T) {
	// valid N from the key
	assert.NoError(t, ValidateN(paillierPublic.n.Modulus))

	assert.ErrorIs(t, ValidateN(nil), ErrPaillierNil)

	// wrong length
	assert.ErrorIs(t, ValidateN(saferith.ModulusFromUint64(101)), ErrPaillierLength)

	// even 2048-bit modulus
	evenBig := new(big.Int).Lsh(big.NewInt(1), 2047)
	evenBig.Add(evenBig, big.NewInt(2)) // 2^2047 + 2, even with 2048 bits
	evenN := saferith.ModulusFromNat(new(saferith.Nat).SetBig(evenBig, 2048))
	assert.ErrorIs(t, ValidateN(evenN), ErrPaillierEven)
}

func TestPublicKey_WriteToDomain(t *testing.T) {
	var buf bytes.Buffer
	n, err := paillierPublic.WriteTo(&buf)
	require.NoError(t, err)
	assert.Equal(t, int64(len(buf.Bytes())), n)
	assert.Len(t, buf.Bytes(), 256)
	assert.Equal(t, "Paillier PublicKey", paillierPublic.Domain())

	var nilPk *PublicKey
	_, err = nilPk.WriteTo(&buf)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestPublicKey_ModulusAccessors(t *testing.T) {
	assert.Equal(t, paillierPublic.n, paillierPublic.Modulus())
	assert.Equal(t, paillierPublic.nSquared, paillierPublic.ModulusSquared())
}

func TestEncWithNonce_PanicOutOfRange(t *testing.T) {
	// encrypting m ≥ (N-1)/2 must panic
	nHalf := new(saferith.Nat).SetNat(paillierPublic.nNat)
	nHalf.Rsh(nHalf, 1, -1)
	two := new(saferith.Nat).SetUint64(2)
	outOfRange := new(saferith.Nat).Add(nHalf, two, -1)
	big := new(saferith.Int).SetNat(outOfRange)
	assert.Panics(t, func() {
		paillierPublic.EncWithNonce(big, sample.UnitModN(rand.Reader, paillierPublic.n.Modulus))
	})
}
