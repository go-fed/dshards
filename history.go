package dshards

import (
	"bytes"
	"fmt"

	"github.com/cjslep/syrup"
)

const (
	kRev    = "revision"
	kRevSig = "rev-sig"
	kHist   = "history"
)

type Revision struct {
	n      int64
	iv     []byte
	encLoc []byte
}

type RevSig struct {
	rev Revision
	sig []byte
}

type HistoryVerifyOnly struct {
	revsigs []RevSig
	// For verification
	p PublicKeyer
	s Suite
}

type HistoryReadOnly struct {
	HistoryVerifyOnly
	readKey SymmetricKey
}

type History struct {
	HistoryReadOnly
	priv PrivateKeyer
}

func NewHistoryVerifyOnly(s Suite, p PublicKeyer) *HistoryVerifyOnly {
	return &HistoryVerifyOnly{
		s: s,
		p: p,
	}
}

func NewHistoryReadOnly(s Suite, p PublicKeyer, read SymmetricKey) *HistoryReadOnly {
	return &HistoryReadOnly{
		HistoryVerifyOnly: HistoryVerifyOnly{
			s: s,
			p: p,
		},
		readKey: read,
	}
}

func NewHistory(s Suite, p PrivateKeyer, read SymmetricKey) *History {
	return &History{
		HistoryReadOnly: HistoryReadOnly{
			HistoryVerifyOnly: HistoryVerifyOnly{
				s: s,
				p: p,
			},
			readKey: read,
		},
		priv: p,
	}
}

func (r Revision) syrup() interface{} {
	return []interface{}{
		kRev,
		r.n,
		r.iv,
		r.encLoc,
	}
}

func (r Revision) signingBytes() (b []byte, err error) {
	hv := r.syrup()
	var buf bytes.Buffer
	err = syrup.NewEncoder(syrup.NewPrototypeEncoding(), &buf).Encode(hv)
	b = buf.Bytes()
	return
}

func (r *Revision) unsyrup(v interface{}) (err error) {
	if vs, ok := v.([]interface{}); !ok {
		err = fmt.Errorf("revision not []interface: %T", v)
	} else if len(vs) != 4 {
		err = fmt.Errorf("revision not len=4: %d", len(vs))
	} else if str, ok := vs[0].(string); !ok || str != kRev {
		err = fmt.Errorf("revision elem[0] not string or not %q: %v", kRev, vs[0])
	} else if n, ok := vs[1].(int64); !ok {
		err = fmt.Errorf("revision elem[1] not int64: %T", vs[1])
	} else if iv, ok := vs[2].([]byte); !ok {
		err = fmt.Errorf("revision elem[2] not []byte: %T", vs[2])
	} else if encLoc, ok := vs[3].([]byte); !ok {
		err = fmt.Errorf("revision elem[3] not []byte: %T", vs[3])
	} else {
		r.n = n
		r.iv = iv
		r.encLoc = encLoc
	}
	return
}

func (r RevSig) syrup() interface{} {
	return []interface{}{
		kRevSig,
		r.rev.syrup(),
		r.sig,
	}
}

func (r *RevSig) unsyrup(v interface{}) (err error) {
	if vs, ok := v.([]interface{}); !ok {
		err = fmt.Errorf("revsig not []interface: %T", v)
	} else if len(vs) != 3 {
		err = fmt.Errorf("revsig not len=3: %d", len(vs))
	} else if str, ok := vs[0].(string); !ok || str != kRevSig {
		err = fmt.Errorf("revsig elem[0] not string or not %q: %v", kRevSig, vs[0])
	} else if sig, ok := vs[2].([]byte); !ok {
		err = fmt.Errorf("revsig elem[2] not []byte: %T", vs[2])
	} else {
		rev := &Revision{}
		if err = rev.unsyrup(vs[1]); err != nil {
			return
		}
		r.rev = *rev
		r.sig = sig
	}
	return
}

func (h *HistoryVerifyOnly) Len() int {
	return len(h.revsigs)
}

func (h *HistoryReadOnly) ReadURN(i int) (u URN, err error) {
	var plain []byte
	if plain, err = decryptURN(h.revsigs[i].rev.encLoc, h.revsigs[i].rev.iv, h.readKey, h.s); err != nil {
		return
	}

	u, err = ParseURN(string(plain))
	return
}

func (h *History) Write(p PublicShard) (err error) {
	var r RevSig
	r.rev.n = int64(len(h.revsigs))
	r.rev.encLoc, r.rev.iv, err = encryptURN([]byte(p.Address.String()), h.readKey, h.s)
	if err != nil {
		return
	}
	var sigb []byte
	if sigb, err = r.rev.signingBytes(); err != nil {
		return
	}
	if r.sig, err = signRevision(h.priv.PrivateKey(), sigb, h.s); err != nil {
		return
	}
	h.revsigs = append(h.revsigs, r)
	return
}

func (h *HistoryVerifyOnly) Verify(i int) (err error) {
	var sigb []byte
	if sigb, err = h.revsigs[i].rev.signingBytes(); err != nil {
		return
	}

	pub := h.p.PublicKey()
	err = verifyRevision(&pub, sigb, h.revsigs[i].sig, h.s)
	return
}

func (h *HistoryVerifyOnly) Unmarshal(b []byte) (err error) {
	buf := bytes.NewBuffer(b)

	var v interface{}
	err = syrup.NewDecoder(syrup.NewPrototypeEncoding(), buf).Decode(&v)
	if err != nil {
		return
	} else if vs, ok := v.([]interface{}); !ok {
		err = fmt.Errorf("history unexpected type: %T", v)
		return
	} else if len(vs) < 1 {
		err = fmt.Errorf("history missing prefix: len %d", len(vs))
		return
	} else if str, ok := vs[0].(string); !ok || str != kHist {
		err = fmt.Errorf("history elem[0] not string or not %q: %v", kHist, vs[0])
		return
	} else if len(vs) == 1 {
		// Empty
		return
	} else if len(vs) != 2 {
		err = fmt.Errorf("history not len=2: %d", len(vs))
		return
	} else if rsi, ok := vs[1].([]interface{}); !ok {
		err = fmt.Errorf("history elem[0] not []interface: %T", vs[1])
		return
	} else {
		h.revsigs = make([]RevSig, len(rsi))
		for i, ele := range rsi {
			if err = (&(h.revsigs[i])).unsyrup(ele); err != nil {
				return
			}
		}
	}
	return
}

func (h HistoryVerifyOnly) Marshal() (b []byte, err error) {
	v := make([]interface{}, len(h.revsigs))
	for i, rs := range h.revsigs {
		v[i] = rs.syrup()
	}
	hv := []interface{}{
		kHist,
	}
	if len(v) > 0 {
		hv = append(hv, v)
	}
	var buf bytes.Buffer
	err = syrup.NewEncoder(syrup.NewPrototypeEncoding(), &buf).Encode(hv)
	b = buf.Bytes()
	return
}
