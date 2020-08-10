package dshards

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Cap represents any capability. Can be type-asserted to VerifyCap, ReadCap,
// or ReadWriteCap.
type Cap interface {
	String() string
	KeyDataURN() (URN, error)
}

// VerifyCap is the basic verifiable capability of a mutable datashard.
type VerifyCap interface {
	Cap
}

// ReadCap is the capability that can verify, read the location of, and decrypt
// the contents of the mutable datashard.
type ReadCap interface {
	VerifyCap
	VerifyCap() VerifyCap
}

// ReadWriteCap is the capability that can verify, read the location of, decrypt
// the contents of, and write new revisions of a mutable datashard.
type ReadWriteCap interface {
	ReadCap
	ReadCap() ReadCap
}

type accessLevel string

const (
	verifyAL accessLevel = "v"
	readAL   accessLevel = "r"
	writeAL  accessLevel = "w"
)

func toAccessLevel(s string) (a accessLevel, err error) {
	switch accessLevel(s) {
	case verifyAL:
		a = verifyAL
	case readAL:
		a = readAL
	case writeAL:
		a = writeAL
	default:
		err = fmt.Errorf("unknown access level: %q", s)
	}
	return
}

func toVersion(s []string) (n int, hash []byte, err error) {
	if len(s) > 2 {
		err = errors.New("malformed mdsc: too many versions")
		return
	} else if len(s) == 0 {
		return noVersionProvided, nil, nil
	}
	var i int64
	i, err = strconv.ParseInt(s[0], 10, 64)
	if err != nil {
		return
	}
	n = int(i)
	if n < 0 {
		err = fmt.Errorf("malformed mdsc: negative version %d", n)
		return
	}
	if len(s) > 1 {
		hash, err = base64.RawURLEncoding.DecodeString(s[1])
	}
	return
}

var _ VerifyCap = new(verifyMDSC)

// verifyMDSC only contains enough information to verify a mutable datashard's
// existence.
type verifyMDSC struct {
	a              accessLevel
	s              Suite
	keyDataHash    []byte
	keyDataSymmKey SymmetricKey
	// TODO: Why have nVersion, and not prevHashVersion?
	nVersion    int
	hashVersion []byte
}

var _ ReadCap = new(readMDSC)

// readMDSC contains enough information to locate (and presumably fetch) a
// mutable datashard, as well as decrypt its contents.
type readMDSC struct {
	verifyMDSC
	readKey SymmetricKey
}

var _ ReadWriteCap = new(mdsc)

// mdsc is a mutable Datashard. It contains all private key information for all
// capabilities.
type mdsc struct {
	verifyMDSC
	writeKey SymmetricKey
}

const (
	noVersionProvided = -1
	mdscPrefix        = "mdsc"
	mdscDelim         = idscDelim
	// TODO Why not have versioningDelim = idscDelim?
	versioningDelim = "/"
)

// ParseMDSC parses a string mutable datashard identifier into its capability.
func ParseMDSC(s string) (c Cap, err error) {
	ss := strings.Split(s, protocolDelim)
	if len(ss) != 2 {
		err = errors.New("malformed mdsc")
		return
	} else if ss[0] != mdscPrefix {
		err = errors.New("malformed mdsc: not prefixed with 'mdsc'")
		return
	}
	ps := strings.Split(ss[1], mdscDelim)
	if len(ps) < 4 || len(ps) > 5 {
		err = errors.New("malformed mdsc")
		return
	}
	m := verifyMDSC{nVersion: noVersionProvided}
	m.a, err = toAccessLevel(ps[0])
	if err != nil {
		return
	}
	m.s, err = toSuite(ps[1])
	if err != nil {
		return
	}
	m.keyDataHash, err = base64.RawURLEncoding.DecodeString(ps[2])
	if err != nil {
		return
	}
	// Detect & split the versioning at the end
	if len(ps) == 4 {
		vs := strings.Split(ps[3], versioningDelim)
		m.keyDataSymmKey, err = base64.RawURLEncoding.DecodeString(vs[0])
		if err != nil {
			return
		}
		m.nVersion, m.hashVersion, err = toVersion(vs[1:])
		if err != nil {
			return
		}
		c = &m
	}
	if len(ps) == 5 {
		m.keyDataSymmKey, err = base64.RawURLEncoding.DecodeString(ps[3])
		if err != nil {
			return
		}
		vs := strings.Split(ps[4], versioningDelim)
		if m.a == readAL {
			r := readMDSC{verifyMDSC: m}
			r.readKey, err = base64.RawURLEncoding.DecodeString(vs[0])
			if err != nil {
				return
			}
			r.nVersion, r.hashVersion, err = toVersion(vs[1:])
			if err != nil {
				return
			}
			c = &r
		} else if m.a == writeAL {
			w := mdsc{verifyMDSC: m}
			w.writeKey, err = base64.RawURLEncoding.DecodeString(vs[0])
			if err != nil {
				return
			}
			w.nVersion, w.hashVersion, err = toVersion(vs[1:])
			if err != nil {
				return
			}
			c = &w
		} else {
			err = errors.New("malformed mdsc: provided read|write key for non-read non-write mdsc")
			return
		}
	}
	return
}

func (m verifyMDSC) baseString() string {
	var buf strings.Builder
	buf.WriteString(mdscPrefix)
	buf.WriteString(protocolDelim)

	buf.WriteString(string(m.a))
	buf.WriteString(mdscDelim)

	buf.WriteString(string(m.s))
	buf.WriteString(mdscDelim)

	dst := make([]byte, base64.RawURLEncoding.EncodedLen(len(m.keyDataHash)))
	base64.RawURLEncoding.Encode(dst, m.keyDataHash)
	buf.Write(dst)
	buf.WriteString(mdscDelim)

	dst = make([]byte, base64.RawURLEncoding.EncodedLen(len(m.keyDataSymmKey)))
	base64.RawURLEncoding.Encode(dst, m.keyDataSymmKey)
	buf.Write(dst)
	return buf.String()
}

func (m verifyMDSC) versionSuffixString() string {
	var buf strings.Builder
	if m.nVersion != noVersionProvided {
		buf.WriteString(versioningDelim)
		buf.WriteString(strconv.FormatInt(int64(m.nVersion), 10))
		// TODO: Trailing slash?
		buf.WriteString(versioningDelim)
		if len(m.hashVersion) > 0 {
			dst := make([]byte, base64.RawURLEncoding.EncodedLen(len(m.hashVersion)))
			base64.RawURLEncoding.Encode(dst, m.hashVersion)
			buf.Write(dst)
		}
	}
	return buf.String()
}

func (m verifyMDSC) KeyDataURN() (URN, error) {
	return newURNForSuite(m.s, m.keyDataHash)
}

func (m verifyMDSC) String() string {
	var buf strings.Builder
	buf.WriteString(m.baseString())
	buf.WriteString(m.versionSuffixString())
	return buf.String()
}

func (m readMDSC) String() string {
	var buf strings.Builder
	buf.WriteString(m.verifyMDSC.baseString())

	buf.WriteString(mdscDelim)
	dst := make([]byte, base64.RawURLEncoding.EncodedLen(len(m.readKey)))
	base64.RawURLEncoding.Encode(dst, m.readKey)
	buf.Write(dst)

	buf.WriteString(m.versionSuffixString())
	return buf.String()
}

func (m mdsc) String() string {
	var buf strings.Builder
	buf.WriteString(m.verifyMDSC.baseString())

	buf.WriteString(mdscDelim)
	dst := make([]byte, base64.RawURLEncoding.EncodedLen(len(m.writeKey)))
	base64.RawURLEncoding.Encode(dst, m.writeKey)
	buf.Write(dst)

	buf.WriteString(m.versionSuffixString())
	return buf.String()
}

func (m mdsc) ReadCap() ReadCap {
	r := &readMDSC{
		verifyMDSC: verifyMDSC{
			a:              readAL,
			s:              m.s,
			keyDataHash:    make([]byte, len(m.keyDataHash)),
			keyDataSymmKey: make([]byte, len(m.keyDataSymmKey)),
			nVersion:       m.nVersion,
			hashVersion:    make([]byte, len(m.hashVersion)),
		},
		readKey: nil,
	}
	copy(r.keyDataHash, m.keyDataHash)
	copy(r.keyDataSymmKey, m.keyDataSymmKey)
	copy(r.hashVersion, m.hashVersion)
	r.readKey = toReadKey(m.writeKey)
	return r
}

func (m mdsc) VerifyCap() VerifyCap {
	v := &verifyMDSC{
		a:              verifyAL,
		s:              m.s,
		keyDataHash:    make([]byte, len(m.keyDataHash)),
		keyDataSymmKey: make([]byte, len(m.keyDataSymmKey)),
		nVersion:       m.nVersion,
		hashVersion:    make([]byte, len(m.hashVersion)),
	}
	copy(v.keyDataHash, m.keyDataHash)
	copy(v.keyDataSymmKey, m.keyDataSymmKey)
	copy(v.hashVersion, m.hashVersion)
	return v
}

func (r readMDSC) VerifyCap() VerifyCap {
	v := &verifyMDSC{
		a:              verifyAL,
		s:              r.s,
		keyDataHash:    make([]byte, len(r.keyDataHash)),
		keyDataSymmKey: make([]byte, len(r.keyDataSymmKey)),
		nVersion:       r.nVersion,
		hashVersion:    make([]byte, len(r.hashVersion)),
	}
	copy(v.keyDataHash, r.keyDataHash)
	copy(v.keyDataSymmKey, r.keyDataSymmKey)
	copy(v.hashVersion, r.hashVersion)
	return v
}
