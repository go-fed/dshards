package dshards

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/cjslep/syrup"
)

const (
	kKeyData = "keydata"
	kKeyNote = "rsa-pcks1-sha256"
)

type PublicKeyer interface {
	PublicKey() rsa.PublicKey
}

type PrivateKeyer interface {
	PublicKeyer
	PrivateKey() *rsa.PrivateKey
}

var _ PublicKeyer = new(EncryptedKeyData)

type EncryptedKeyData struct {
	vk    rsa.PublicKey
	encwk []byte
}

var _ PublicKeyer = new(DecryptedKeyData)
var _ PrivateKeyer = new(DecryptedKeyData)

type DecryptedKeyData struct {
	vk rsa.PublicKey
	wk *rsa.PrivateKey
	// Used to encrypt the write-key (wk)
	key SymmetricKey
	s   Suite
}

func NewDecryptedKeyData(key SymmetricKey, s Suite) *DecryptedKeyData {
	return &DecryptedKeyData{key: key, s: s}
}

func (e EncryptedKeyData) PublicKey() rsa.PublicKey {
	return e.vk
}

func (d DecryptedKeyData) PublicKey() rsa.PublicKey {
	return d.vk
}

func (d DecryptedKeyData) PrivateKey() *rsa.PrivateKey {
	return d.wk
}

func (k *EncryptedKeyData) Unmarshal(b []byte) (err error) {
	buf := bytes.NewBuffer(b)
	var v interface{}
	err = syrup.NewDecoder(syrup.NewPrototypeEncoding(), buf).Decode(&v)
	if err != nil {
		return
	}

	var vs []interface{}
	var ok bool
	if vs, ok = v.([]interface{}); !ok {
		err = fmt.Errorf("decoded keydata is not a []interface{}: %T", v)
		return
	}
	if len(vs) != 3 {
		err = fmt.Errorf("decoded keydata not len() 3: %d", len(vs))
		return
	}
	if s, ok := vs[0].(string); !ok || s != kKeyData {
		err = fmt.Errorf("decoded keydata first item not %q: %s", kKeyData, vs[0])
		return
	}

	// Handle public key list
	if vs1, ok := vs[1].([]interface{}); !ok {
		err = fmt.Errorf("decoded keydata second item not list: %T", vs[1])
		return
	} else {
		if len(vs1) != 2 {
			err = fmt.Errorf("decoded keydata public key list not len() 2: %d", len(vs1))
			return
		} else if s, ok := vs1[0].(string); !ok || s != kKeyNote {
			err = fmt.Errorf("decoded keydata public key unknown type: %s", vs1[0])
			return
		}
		if m, ok := vs1[1].(map[interface{}]interface{}); !ok {
			err = fmt.Errorf("decoded keydata second item not dict: %T", vs1[1])
			return
		} else if n, ok := m[interface{}("n")]; !ok {
			err = errors.New("decoded keydata second item has no n")
			return
		} else if e, ok := m[interface{}("e")]; !ok {
			err = errors.New("decoded keydata second item has no e")
		} else {
			switch nv := n.(type) {
			case int64:
				k.vk.N = big.NewInt(nv)
			case *big.Int:
				k.vk.N = nv
			default:
				err = fmt.Errorf("decoded keydata publickey n not int64 nor bigint: %T", n)
				return
			}
			switch ev := e.(type) {
			case int64:
				k.vk.E = int(ev)
			default:
				err = fmt.Errorf("decoded keydata publickey e not int64: %T", n)
				return
			}
		}
	}

	// Handle encrypted private key list
	if vs2, ok := vs[2].([]interface{}); !ok {
		err = fmt.Errorf("decoded keydata third item not list: %T", vs[2])
		return
	} else {
		if len(vs2) != 2 {
			err = fmt.Errorf("decoded keydata encrypted private key list not len() 2: %d", len(vs2))
			return
		} else if s, ok := vs2[0].(string); !ok || s != kKeyNote {
			err = fmt.Errorf("decoded keydata encrypted private key unknown type: %s", vs2[0])
			return
		}
		if eb, ok := vs2[1].([]byte); !ok {
			err = fmt.Errorf("decoded keydata encrypted private key not bytes: %T", vs2[1])
			return
		} else {
			k.encwk = eb
		}
	}
	return
}

func (k *DecryptedKeyData) Unmarshal(b []byte) (err error) {
	ek := &EncryptedKeyData{}
	err = ek.Unmarshal(b)
	if err != nil {
		return
	}
	k.vk = ek.vk
	var dec []byte
	dec, err = decryptWriteKey(ek.encwk, k.key, k.s)
	if err != nil {
		return
	}
	buf := bytes.NewBuffer(dec)
	defer buf.Reset()

	var v interface{}
	err = syrup.NewDecoder(syrup.NewPrototypeEncoding(), buf).Decode(&v)
	if err != nil {
		return
	}
	k.wk = &rsa.PrivateKey{}
	if m, ok := v.(map[interface{}]interface{}); !ok {
		err = fmt.Errorf("decoded keydata decrypted private key unexpected type: %T", v)
		return
	} else if di, ok := m[interface{}("d")]; !ok {
		err = errors.New("decoded keydata private write key has no d")
		return
	} else if d, ok := di.(*big.Int); !ok {
		err = fmt.Errorf("decoded keydata private write key d unexpected type: %T", di)
		return
	} else if dpi, ok := m[interface{}("dp")]; !ok {
		err = errors.New("decoded keydata private write key has no dp")
		return
	} else if dp, ok := dpi.(*big.Int); !ok {
		err = fmt.Errorf("decoded keydata private write key dp unexpected type: %T", dpi)
		return
	} else if dqi, ok := m[interface{}("dq")]; !ok {
		err = errors.New("decoded keydata private write key has no dq")
		return
	} else if dq, ok := dqi.(*big.Int); !ok {
		err = fmt.Errorf("decoded keydata private write key dq unexpected type: %T", dqi)
		return
	} else if ei, ok := m[interface{}("e")]; !ok {
		err = errors.New("decoded keydata private write key has no e")
		return
	} else if e, ok := ei.(int64); !ok {
		err = fmt.Errorf("decoded keydata private write key e unexpected type: %T", ei)
		return
	} else if ni, ok := m[interface{}("n")]; !ok {
		err = errors.New("decoded keydata private write key has no n")
		return
	} else if n, ok := ni.(*big.Int); !ok {
		err = fmt.Errorf("decoded keydata private write key n unexpected type: %T", ni)
		return
	} else if pi, ok := m[interface{}("p")]; !ok {
		err = errors.New("decoded keydata private write key has no p")
		return
	} else if p, ok := pi.(*big.Int); !ok {
		err = fmt.Errorf("decoded keydata private write key p unexpected type: %T", pi)
		return
	} else if qi, ok := m[interface{}("q")]; !ok {
		err = errors.New("decoded keydata private write key has no q")
		return
	} else if q, ok := qi.(*big.Int); !ok {
		err = fmt.Errorf("decoded keydata private write key q unexpected type: %T", qi)
		return
	} else if qInvi, ok := m[interface{}("qInv")]; !ok {
		err = errors.New("decoded keydata private write key has no qInv")
		return
	} else if qInv, ok := qInvi.(*big.Int); !ok {
		err = fmt.Errorf("decoded keydata private write key qInv unexpected type: %T", qInvi)
		return
	} else {
		k.wk.D = d
		k.wk.Precomputed.Dp = dp
		k.wk.Precomputed.Dq = dq
		k.wk.PublicKey.E = int(e)
		k.wk.PublicKey.N = n
		k.wk.Primes = []*big.Int{p, q}
		k.wk.Precomputed.Qinv = qInv
	}
	return
}

func (k EncryptedKeyData) Marshal() (b []byte, err error) {
	var buf bytes.Buffer
	v := []interface{}{
		kKeyData,
		[]interface{}{
			kKeyNote,
			pubKey{
				N: k.vk.N,
				E: k.vk.E,
			},
		},
		[]interface{}{
			kKeyNote,
			k.encwk,
		},
	}
	err = syrup.NewEncoder(syrup.NewPrototypeEncoding(), &buf).Encode(v)
	b = buf.Bytes()
	return
}

func (k DecryptedKeyData) Marshal() (b []byte, err error) {
	var buf bytes.Buffer
	v := []interface{}{
		kKeyData,
		[]interface{}{
			kKeyNote,
			pubKey{
				N: k.vk.N,
				E: k.vk.E,
			},
		},
	}
	// Append entire []interface{} as the third item.
	if len(k.wk.Primes) != 2 {
		err = fmt.Errorf("dshards: keydata cannot serialize %d primes", len(k.wk.Primes))
		return
	}
	k.wk.Precompute()
	var toEncBuf bytes.Buffer
	defer toEncBuf.Reset()
	encV := privKey{
		D:    k.wk.D,
		Dp:   k.wk.Precomputed.Dp,
		Dq:   k.wk.Precomputed.Dq,
		E:    k.wk.PublicKey.E,
		N:    k.wk.PublicKey.N,
		P:    k.wk.Primes[0],
		Q:    k.wk.Primes[1],
		QInv: k.wk.Precomputed.Qinv,
	}
	err = syrup.NewEncoder(syrup.NewPrototypeEncoding(), &toEncBuf).Encode(encV)
	if err != nil {
		return
	}
	var enc []byte
	enc, err = encryptWriteKey(toEncBuf.Bytes(), k.key, k.s)
	if err != nil {
		return
	}
	v = append(v, []interface{}{
		kKeyNote,
		enc,
	})
	err = syrup.NewEncoder(syrup.NewPrototypeEncoding(), &buf).Encode(v)
	b = buf.Bytes()
	return
}
