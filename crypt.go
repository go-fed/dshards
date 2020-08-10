package dshards

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
)

// SymmetricKey types these bytes as a symmetric key, which should be treated
// with the same care as a private key.
type SymmetricKey []byte

// PrivateShard is encrypted content that contains the symmetric key. Sharing a
// PrivateShard grants access to the decrypted content.
type PrivateShard struct {
	// Encrypted shard content.
	Content []byte
	// The IDSC address. Sharing this publicly also shares the symmetric
	// key.
	AddressAndKey IDSC
}

// PublicShard returns a public version of this shard, which allows sharing the
// encrypted content without also granting access to the decrypted content.
//
// Note that the PublicShard and PrivateShard's Content share the same
// underlying backing byte slice to save memory.
func (p PrivateShard) PublicShard() (PublicShard, error) {
	urn, err := p.AddressAndKey.URN()
	return PublicShard{
		Content: p.Content,
		Address: urn,
	}, err
}

// PublicShard is encrypted content lacking the symmetric key. Sharing a
// PublicShard does not grant access to the decrypted contents.
type PublicShard struct {
	// Encrypted shard content.
	Content []byte
	// The URN address. Sharing this publicly allows everyone to freely
	// find the address to this bit of content without sharing the
	// symmetric key.
	Address URN
}

// Encrypt applies the Datashards encryption and sharding algorithm.
func Encrypt(plain []byte, key SymmetricKey, s Suite) (rootIdx int, priv []PrivateShard, err error) {
	r := raw{content: plain}
	return encrypt(r, key, s)
}

func encrypt(c chunker, key SymmetricKey, s Suite) (rootIdx int, priv []PrivateShard, err error) {
	var plain [][]byte
	plain, err = c.Chunk()
	if err != nil {
		return
	}
	priv = make([]PrivateShard, len(plain))
	m := manifest{
		urns: make([]URN, len(plain)),
	}
	// Use entry-point IV if content fits within a single shard. Otherwise,
	// use the content IV.
	var ivFn ivFunc
	if len(plain) == 1 {
		ivFn = ivEntryPoint
	} else {
		ivFn = ivContent
	}
	for i, plainChunk := range plain {
		priv[i], err = encryptChunk(plainChunk, key, s, uint64(i), ivFn)
		if err != nil {
			return
		}
		m.urns[i], err = priv[i].AddressAndKey.URN()
		if err != nil {
			return
		}
	}
	if len(priv) == 1 {
		rootIdx = 0
	} else {
		var more []PrivateShard
		rootIdx, more, err = encrypt(m, key, s)
		if err != nil {
			return
		}
		rootIdx += len(priv)
		priv = append(priv, more...)
	}
	return
}

func encryptChunk(plain []byte, key SymmetricKey, s Suite, ctr uint64, ivFn ivFunc) (priv PrivateShard, err error) {
	var block cipher.Block
	block, err = s.blockCipher(key)
	if err != nil {
		return
	}
	var ch crypto.Hash
	ch, err = s.ivHash()
	if err != nil {
		return
	}
	var iv []byte
	iv, err = ivFn(ctr, key)
	if err != nil {
		return
	}
	h := ch.New()
	h.Write(iv)
	ivo := h.Sum(nil)
	ivt := ivo[:block.BlockSize()]
	stream := cipher.NewCTR(block, ivt)

	ciphertext := make([]byte, len(plain))
	stream.XORKeyStream(ciphertext, plain)

	var idsc IDSC
	idsc, err = NewIDSC(s, ciphertext, key)
	if err != nil {
		return
	}
	priv = PrivateShard{
		Content:       ciphertext,
		AddressAndKey: idsc,
	}
	return
}

// Result holds one and only one outcome of a decrypt operation. It may be
// needed for future decryption calls.
type Result struct {
	fetch   []URN
	content []byte

	// Internal: If a manifest exists, the length of the content specified
	// in the manifest. Set when 'fetch' is set.
	contentLen int64
}

// ToFetch contains additional URN addresses to obtain and decrypt using
// DecryptAll. The SymmetricKey for the additional URNs is the same as
// the SymmetricKey used in the PrivateShard that gave this Result.
//
// How to obtain the additional URN addresses is up to the client. Order of
// results is significant: future calls to decrypt must supply shards in the
// same order as listed by the URNs.
//
// Empty if no more to fetch.
func (r *Result) ToFetch() []URN {
	return r.fetch
}

// Content is the unencrypted content.
func (r *Result) Content() []byte {
	return r.content
}

// Decrypt applies the Datashards decryption algorithm onto the root Datashard.
//
// The Result will either indicate that more data is needed or provide the
// decrypted content. If more data is needed, use DecryptFetchedResult.
func Decrypt(root PrivateShard, s Suite) (r *Result, err error) {
	var pt []byte
	pt, err = decryptChunk(root.Content, root.AddressAndKey.symmKey, s, 0, ivEntryPoint)
	if err != nil {
		return
	}
	r, err = decode(pt)
	return
}

// DecryptFetchedResult applies the Datashards decryption algorithm to the
// Datashards obtained from a Result that indicated more data was needed in
// ToFetch.
//
// The results in priv must be in the same order as listed in the Result.
func DecryptFetchedResult(prev *Result, priv []PrivateShard, s Suite) (next *Result, err error) {
	next = &Result{}

	// Decrypt all chunks.
	for i, pr := range priv {
		var pt []byte
		pt, err = decryptChunk(pr.Content, pr.AddressAndKey.symmKey, s, uint64(i), ivContent)
		if err != nil {
			return
		}
		var r *Result
		r, err = decode(pt)
		if err != nil {
			return
		} else if len(r.fetch) > 0 {
			err = fmt.Errorf("malformed datashard: decrypting %dth fetched results encountered unexpected type %q", i, kManifest)
			return
		}
		next.content = append(next.content, r.content...)
	}

	// Check the length and maybe eliminate padding.
	if int64(len(next.content)) < prev.contentLen {
		err = fmt.Errorf("malformed datashard: decrypting yielded %d of %d bytes", len(next.content), prev.contentLen)
		return
	} else if int64(len(next.content)) > prev.contentLen {
		next.content = next.content[:prev.contentLen]
	}

	// Determine if this is a manifest -- an error will arise if it is not.
	maybeManifest, errM := decode(next.content)
	if errM == nil {
		next = maybeManifest
	} else {
		// Ignore, it is raw content
	}
	return
}

func decryptChunk(ciphertext []byte, key SymmetricKey, s Suite, ctr uint64, ivFn ivFunc) (plaintext []byte, err error) {
	var block cipher.Block
	block, err = s.blockCipher(key)
	if err != nil {
		return
	}
	var ch crypto.Hash
	ch, err = s.ivHash()
	if err != nil {
		return
	}
	var iv []byte
	iv, err = ivFn(ctr, key)
	if err != nil {
		return
	}
	h := ch.New()
	h.Write(iv)
	ivo := h.Sum(nil)
	ivt := ivo[:block.BlockSize()]
	stream := cipher.NewCTR(block, ivt)

	plaintext = make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return
}

// Initialization vector

const (
	ivEntryPointPrefix = "entry-point"
	ivContentPrefix    = "content"
)

type ivFunc func(ctr uint64, key SymmetricKey) ([]byte, error)

// Generates the initialization vector required for the first entry-point
// datashard.
//
// The initialization vector is not truncated to any particular size.
func ivEntryPoint(ctr uint64, key SymmetricKey) ([]byte, error) {
	return generateIV(ivEntryPointPrefix, ctr, key)
}

// Generates the initialization vector required for a content datashard.
//
// The initialization vector is not truncated to any particular size.
func ivContent(ctr uint64, key SymmetricKey) ([]byte, error) {
	return generateIV(ivContentPrefix, ctr, key)
}

// generateIV applies the initialization vector creation algorithm.
func generateIV(prefix string, ctr uint64, key SymmetricKey) ([]byte, error) {
	cbuf := new(bytes.Buffer)
	err := binary.Write(cbuf, binary.LittleEndian, ctr)
	return append([]byte(prefix), append(cbuf.Bytes(), key...)...), err
}

// MDSC

// toReadKey generates the read symmetric key from the write symmetric key.
func toReadKey(writeKey SymmetricKey) SymmetricKey {
	r := sha256.Sum256(writeKey)
	return r[:]
}

type pubKey struct {
	N *big.Int `syrup:"n"`
	E int      `syrup:"e"`
}

type privKey struct {
	D    *big.Int `syrup:"d"`
	Dp   *big.Int `syrup:"dp"`
	Dq   *big.Int `syrup:"dq"`
	E    int      `syrup:"e"`
	N    *big.Int `syrup:"n"`
	P    *big.Int `syrup:"p"`
	Q    *big.Int `syrup:"q"`
	QInv *big.Int `syrup:"qInv"`
}

// Encrypts the write key for a KeyData entry.
func encryptWriteKey(plain []byte, key SymmetricKey, s Suite) (enc []byte, err error) {
	var block cipher.Block
	block, err = s.blockCipher(key)
	if err != nil {
		return
	}
	// Zeroed IV
	iv := make([]byte, block.BlockSize())
	stream := cipher.NewCTR(block, iv)

	enc = make([]byte, len(plain))
	stream.XORKeyStream(enc, plain)
	return
}

// Decrypts the write key for a KeyData entry.
func decryptWriteKey(crypt []byte, key SymmetricKey, s Suite) (plain []byte, err error) {
	var block cipher.Block
	block, err = s.blockCipher(key)
	if err != nil {
		return
	}
	// Zeroed IV
	iv := make([]byte, block.BlockSize())
	stream := cipher.NewCTR(block, iv)

	plain = make([]byte, len(crypt))
	stream.XORKeyStream(plain, crypt)
	return
}

// Encrypts the URN in a history entry
func encryptURN(plain []byte, key SymmetricKey, s Suite) (crypt, iv []byte, err error) {
	var block cipher.Block
	block, err = s.blockCipher(key)
	if err != nil {
		return
	}
	iv = make([]byte, block.BlockSize())
	var n int
	n, err = rand.Read(iv)
	if err != nil {
		return
	} else if n != block.BlockSize() {
		err = fmt.Errorf("crypto/rand read %d of %d bytes", n, block.BlockSize())
		return
	}
	stream := cipher.NewCTR(block, iv)

	crypt = make([]byte, len(plain))
	stream.XORKeyStream(crypt, plain)
	return
}

// Decrypts the URN in a history entry
func decryptURN(crypt, iv []byte, key SymmetricKey, s Suite) (plain []byte, err error) {
	var block cipher.Block
	block, err = s.blockCipher(key)
	if err != nil {
		return
	}
	stream := cipher.NewCTR(block, iv)

	plain = make([]byte, len(crypt))
	stream.XORKeyStream(plain, crypt)
	return
}

// Signs the revision in a history entry
func signRevision(priv *rsa.PrivateKey, toSign []byte, s Suite) (sig []byte, err error) {
	var ch crypto.Hash
	ch, err = s.historySignatureHash()
	if err != nil {
		return
	}

	h := ch.New()
	h.Write(toSign)
	hashToSign := h.Sum(nil)
	sig, err = rsa.SignPKCS1v15(rand.Reader, priv, ch, hashToSign)
	return
}

// Verifies the revision in a history entry
func verifyRevision(pub *rsa.PublicKey, toVerify, sig []byte, s Suite) (err error) {
	var ch crypto.Hash
	ch, err = s.historySignatureHash()
	if err != nil {
		return
	}

	h := ch.New()
	h.Write(toVerify)
	hashToVerify := h.Sum(nil)
	err = rsa.VerifyPKCS1v15(pub, ch, hashToVerify, sig)
	return
}
