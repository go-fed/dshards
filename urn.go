package dshards

import (
	"encoding/base64"
	"errors"
	"hash"
	"strings"
)

const (
	urnPrefix = "urn"
	urnDelim  = ":"
)

// URN is an address for a Datashard without containing the SymmetricKey.
// Handing the URN out allows people to find the content, but they cannot
// decrypt and access it.
type URN struct {
	dhash Hash
	hash  []byte
}

// Parse turns a URN string into a URN.
func ParseURN(s string) (su URN, err error) {
	ss := strings.Split(s, urnDelim)
	if len(ss) != 3 {
		err = errors.New("malformed urn: expecting 3 parts")
		return
	} else if ss[0] != urnPrefix {
		err = errors.New("malformed urn: not prefixed with 'urn'")
		return
	}
	su.dhash, err = toHash(ss[1])
	if err != nil {
		return
	}
	su.hash, err = base64.RawURLEncoding.DecodeString(ss[2])
	return
}

// Creates the URN for the given content and datashards hash scheme.
//
// Expensive as it computes the hash of the content.
func NewURN(dsh Hash, content []byte) (s URN, err error) {
	var h hash.Hash
	h, err = dsh.Hash()
	if err != nil {
		return
	}
	h.Write(content)
	s.hash = h.Sum(nil)
	s.dhash = dsh
	return
}

// newURNForSuite is an internal constructor for IDSC, when the hash is
// already known.
func newURNForSuite(s Suite, hash []byte) (su URN, err error) {
	su.hash = hash
	su.dhash, err = s.urnHash()
	return
}

func (s URN) String() string {
	b := []byte(urnPrefix)
	b = append(b, []byte(urnDelim)...)
	b = append(b, []byte(s.dhash)...)
	b = append(b, []byte(urnDelim)...)

	dst := make([]byte, base64.RawURLEncoding.EncodedLen(len(s.hash)))
	base64.RawURLEncoding.Encode(dst, s.hash)
	b = append(b, dst...)
	return string(b)
}
