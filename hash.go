package dshards

import (
	"crypto/sha256"
	"fmt"
	"hash"
)

// Hash are datashard-supported hash algorithms for URNs.
type Hash string

const (
	SHA256D Hash = "sha256d"
)

// toHash converts a string into a Hash type.
func toHash(s string) (dsh Hash, err error) {
	switch s {
	case string(SHA256D):
		dsh = SHA256D
	default:
		err = fmt.Errorf("unknown datashards hash %q", s)
	}
	return
}

// toHash interprets a Hash into a Golang Hash type.
func (dsh Hash) Hash() (h hash.Hash, err error) {
	switch dsh {
	case SHA256D:
		h = &doublingHash{sha256.New()}
	default:
		err = fmt.Errorf("unknown datashards hash %q", dsh)
	}
	return
}

var _ hash.Hash = new(doublingHash)

// doublingHash applies a Hash twice.
type doublingHash struct {
	hash.Hash
}

// Sum computes the current hash. It does not modify state.
//
// The Hash interface continues to be golang's most easily misunderstood
// interface.
func (d *doublingHash) Sum(b []byte) []byte {
	once := d.Hash.Sum(nil)
	d.Hash.Reset()
	_, _ = d.Hash.Write(once)
	return d.Hash.Sum(b)
}
