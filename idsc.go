package dshards

import (
	"encoding/base64"
	"errors"
	"strings"
)

const (
	idscPrefix    = "idsc"
	idscDelim     = "."
	protocolDelim = ":"
)

// IDSC is an address for an immutable Datashard. However, this address contains
// the SymmetricKey, so handing it out not only allows people to find the
// content, but also access it.
type IDSC struct {
	s       Suite
	hash    []byte
	symmKey SymmetricKey
}

// ParseIDSC turns an idsc string into a IDSC.
func ParseIDSC(s string) (idsc IDSC, err error) {
	ss := strings.Split(s, protocolDelim)
	if len(ss) != 2 {
		err = errors.New("malformed idsc")
		return
	} else if ss[0] != idscPrefix {
		err = errors.New("malformed idsc: not prefixed with 'idsc'")
		return
	}
	ps := strings.Split(ss[1], idscDelim)
	if len(ps) != 3 {
		err = errors.New("malformed idsc")
		return
	}
	idsc.s, err = toSuite(ps[0])
	if err != nil {
		return
	}
	idsc.hash, err = base64.RawURLEncoding.DecodeString(ps[1])
	if err != nil {
		return
	}
	idsc.symmKey, err = base64.RawURLEncoding.DecodeString(ps[2])
	return
}

// NewIDSC creates the IDSC for the given suite, content, and symmetrical key.
//
// There are no restrictions on the length of content.
func NewIDSC(s Suite, content, key SymmetricKey) (idsc IDSC, err error) {
	var h Hash
	h, err = s.urnHash()
	if err != nil {
		return
	}
	var surn URN
	surn, err = NewURN(h, content)
	if err != nil {
		return
	}
	idsc.s = s
	idsc.hash = surn.hash
	idsc.symmKey = key
	return
}

// URN returns the datashard URN represented by this IDSC.
func (i IDSC) URN() (s URN, err error) {
	return newURNForSuite(i.s, i.hash)
}

func (i IDSC) String() string {
	b := []byte(idscPrefix)
	b = append(b, []byte(protocolDelim)...)
	b = append(b, []byte(i.s)...)
	b = append(b, []byte(idscDelim)...)

	dst := make([]byte, base64.RawURLEncoding.EncodedLen(len(i.hash)))
	base64.RawURLEncoding.Encode(dst, i.hash)
	b = append(b, dst...)
	b = append(b, []byte(idscDelim)...)

	dst = make([]byte, base64.RawURLEncoding.EncodedLen(len(i.symmKey)))
	base64.RawURLEncoding.Encode(dst, i.symmKey)
	b = append(b, dst...)
	return string(b)
}
