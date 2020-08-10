package dshards

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// Suite of encryption protocols supported by Datashards.
type Suite string

const (
	PROTO_ZERO_SUITE Suite = "0p"
)

// toSuite converts a string into a Suite type.
func toSuite(s string) (su Suite, err error) {
	switch s {
	case string(PROTO_ZERO_SUITE):
		su = PROTO_ZERO_SUITE
	default:
		err = fmt.Errorf("unknown datashards suite %q", s)
	}
	return
}

// urnHash retrieves this suite's datashards hash algorithm.
func (s Suite) urnHash() (h Hash, err error) {
	switch s {
	case PROTO_ZERO_SUITE:
		h = SHA256D
	default:
		err = fmt.Errorf("unknown datashards suite %q", s)
	}
	return
}

func (s Suite) ivHash() (h crypto.Hash, err error) {
	switch s {
	case PROTO_ZERO_SUITE:
		h = crypto.SHA256
	default:
		err = fmt.Errorf("unknown datashards suite %q", s)
	}
	return
}

func (s Suite) blockCipher(key SymmetricKey) (c cipher.Block, err error) {
	switch s {
	case PROTO_ZERO_SUITE:
		c, err = aes.NewCipher(key)
	default:
		err = fmt.Errorf("unknown datashards suite %q", s)
	}
	return
}

func (s Suite) historySignatureHash() (h crypto.Hash, err error) {
	switch s {
	case PROTO_ZERO_SUITE:
		h = crypto.SHA256
	default:
		err = fmt.Errorf("unknown datashards suite %q", s)
	}
	return
}
