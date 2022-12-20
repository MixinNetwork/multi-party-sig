package params

const (
	SecParam  = 256
	SecBytes  = SecParam / 8
	OTParam   = 128
	OTBytes   = OTParam / 8
	StatParam = 80

	L                 = 1 * SecParam     // = 256
	LPrime            = 5 * SecParam     // = 1280
	Epsilon           = 2 * SecParam     // = 512
	LPlusEpsilon      = L + Epsilon      // = 768
	LPrimePlusEpsilon = LPrime + Epsilon // 1792

	BitsIntModN  = 8 * SecParam    // = 2048
	BytesIntModN = BitsIntModN / 8 // = 256

	BitsBlumPrime = 4 * SecParam      // = 1024
	BitsPaillier  = 2 * BitsBlumPrime // = 2048

	BytesPaillier   = BitsPaillier / 8  // = 256
	BytesCiphertext = 2 * BytesPaillier // = 512
)
