package randx

import (
	"crypto/rand"
	"math/big"
)

var (
	randFunc = rand.Reader

	// AlphaLower contains runes [abcdefghijklmnopqrstuvwxyz].
	AlphaLower = []rune("abcdefghijklmnopqrstuvwxyz")
)

var ()

// RuneSequence returns a random sequence using the defined allowed runes.
func GenerateRandomString(l int, allowedRunes []rune) (string, error) {
	c := big.NewInt(int64(len(allowedRunes)))
	seq := make([]rune, l)

	for i := 0; i < l; i++ {
		r, err := rand.Int(randFunc, c)
		if err != nil {
			return "", err
		}

		rn := allowedRunes[r.Uint64()]
		seq[i] = rn
	}

	return string(seq), nil
}
