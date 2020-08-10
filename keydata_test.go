package dshards

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strconv"
	"testing"

	"github.com/cjslep/syrup"
)

var testPrivKey *rsa.PrivateKey
var testSymmKey SymmetricKey
var testEncKey []byte

func init() {
	var err error
	testPrivKey, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	testSymmKey = make([]byte, 32)
	n, err := rand.Reader.Read(testSymmKey)
	if err != nil {
		panic(err)
	} else if n != 32 {
		panic(fmt.Sprintf("test symm key read %d of %d bytes", n, 32))
	}

	// Get encrypted bytes of the test private key
	encV := privKey{
		D:    testPrivKey.D,
		Dp:   testPrivKey.Precomputed.Dp,
		Dq:   testPrivKey.Precomputed.Dq,
		E:    testPrivKey.PublicKey.E,
		N:    testPrivKey.PublicKey.N,
		P:    testPrivKey.Primes[0],
		Q:    testPrivKey.Primes[1],
		QInv: testPrivKey.Precomputed.Qinv,
	}
	var toEncBuf bytes.Buffer
	err = syrup.NewEncoder(syrup.NewPrototypeEncoding(), &toEncBuf).Encode(encV)
	if err != nil {
		panic(err)
	}
	testEncKey, err = encryptWriteKey(toEncBuf.Bytes(), testSymmKey, PROTO_ZERO_SUITE)
	if err != nil {
		panic(err)
	}
	// For history_test
	for i, revsig := range revSigDyn1 {
		revSigDyn1[i].rev.encLoc, revSigDyn1[i].rev.iv, err = encryptURN(revsig.rev.encLoc, testSymmKey, PROTO_ZERO_SUITE)
		if err != nil {
			panic(err)
		}
	}
	for i, revsig := range revSigDyn1 {
		sigb, err := revsig.rev.signingBytes()
		if err != nil {
			panic(err)
		}
		sig, err := signRevision(testPrivKey, sigb, PROTO_ZERO_SUITE)
		if err != nil {
			panic(err)
		}
		revSigDyn1[i].sig = sig
	}
}

func TestMarshalDecryptedKeyData(t *testing.T) {
	dk := &DecryptedKeyData{
		vk:  testPrivKey.PublicKey,
		wk:  testPrivKey,
		key: testSymmKey,
		s:   PROTO_ZERO_SUITE,
	}
	b, err := dk.Marshal()
	if err != nil {
		t.Errorf("got error: %s", err)
	}
	expected := append(
		append([]byte(`[7"keydata[16"rsa-pcks1-sha256{1"ni`+
			dk.vk.N.Text(10)+
			`e1"ei`+
			strconv.FormatInt(int64(dk.vk.E), 10)+
			`e}][16"rsa-pcks1-sha256`+
			strconv.FormatInt(int64(len(testEncKey)), 10)+
			":"),
			testEncKey...),
		[]byte("]]")...)
	if !bytes.Equal(b, expected) {
		t.Errorf("got %v, want %v", b, expected)
		t.Errorf("got len %d, want len %d", len(b), len(expected))
	}
}

func TestMarshalEncryptedKeyData(t *testing.T) {
	str := "arbitrary binary bytes"
	ek := &EncryptedKeyData{
		vk:    testPrivKey.PublicKey,
		encwk: []byte(str),
	}
	b, err := ek.Marshal()
	if err != nil {
		t.Errorf("got error: %s", err)
	}
	expected := append(
		append([]byte(`[7"keydata[16"rsa-pcks1-sha256{1"ni`+
			ek.vk.N.Text(10)+
			`e1"ei`+
			strconv.FormatInt(int64(ek.vk.E), 10)+
			`e}][16"rsa-pcks1-sha256`+
			strconv.FormatInt(int64(len(str)), 10)+
			":"),
			[]byte(str)...),
		[]byte("]]")...)
	if !bytes.Equal(b, expected) {
		t.Errorf("got %v, want %v", b, expected)
		t.Errorf("got len %d, want len %d", len(b), len(expected))
	}
}

func TestUnmarshalDecryptedKeyData(t *testing.T) {
	in := append(
		append([]byte(`[7"keydata[16"rsa-pcks1-sha256{1"ni`+
			testPrivKey.PublicKey.N.Text(10)+
			`e1"ei`+
			strconv.FormatInt(int64(testPrivKey.PublicKey.E), 10)+
			`e}][16"rsa-pcks1-sha256`+
			strconv.FormatInt(int64(len(testEncKey)), 10)+
			":"),
			testEncKey...),
		[]byte("]]")...)
	dk := NewDecryptedKeyData(testSymmKey, PROTO_ZERO_SUITE)
	err := dk.Unmarshal(in)
	if err != nil {
		t.Errorf("got error: %s", err)
	} else if dk.vk.N.Cmp(testPrivKey.PublicKey.N) != 0 {
		t.Errorf("got %v, want %v", dk.vk.N.Text(10), testPrivKey.PublicKey.N.Text(10))
	} else if dk.vk.E != testPrivKey.PublicKey.E {
		t.Errorf("got %d, want %d", dk.vk.E, testPrivKey.PublicKey.E)
	} else if dk.wk.PublicKey.N.Cmp(testPrivKey.PublicKey.N) != 0 {
		t.Errorf("got %v, want %v", dk.wk.PublicKey.N.Text(10), testPrivKey.PublicKey.N.Text(10))
	} else if dk.wk.PublicKey.E != testPrivKey.PublicKey.E {
		t.Errorf("got %d, want %d", dk.wk.PublicKey.E, testPrivKey.PublicKey.E)
	} else if dk.wk.D.Cmp(testPrivKey.D) != 0 {
		t.Errorf("got %v, want %v", dk.wk.D.Text(10), testPrivKey.D.Text(10))
	} else if len(dk.wk.Primes) != len(testPrivKey.Primes) || len(dk.wk.Primes) != 2 {
		t.Errorf("got %d, want %d && want 2", len(dk.wk.Primes), len(testPrivKey.Primes))
	} else if dk.wk.Primes[0].Cmp(testPrivKey.Primes[0]) != 0 {
		t.Errorf("got %v, want %v", dk.wk.Primes[0].Text(10), testPrivKey.Primes[0].Text(10))
	} else if dk.wk.Primes[1].Cmp(testPrivKey.Primes[1]) != 0 {
		t.Errorf("got %v, want %v", dk.wk.Primes[1].Text(10), testPrivKey.Primes[1].Text(10))
	}
}

func TestUnmarshalEncryptedKeyData(t *testing.T) {
	str := "arbitrary binary bytes"
	in := append(
		append([]byte(`[7"keydata[16"rsa-pcks1-sha256{1"ni`+
			testPrivKey.PublicKey.N.Text(10)+
			`e1"ei`+
			strconv.FormatInt(int64(testPrivKey.PublicKey.E), 10)+
			`e}][16"rsa-pcks1-sha256`+
			strconv.FormatInt(int64(len(str)), 10)+
			":"),
			[]byte(str)...),
		[]byte("]]")...)
	ek := &EncryptedKeyData{}
	err := ek.Unmarshal(in)
	if err != nil {
		t.Errorf("got error: %s", err)
	} else if ek.vk.N.Cmp(testPrivKey.PublicKey.N) != 0 {
		t.Errorf("got %v, want %v", ek.vk.N.Text(10), testPrivKey.PublicKey.N.Text(10))
	} else if ek.vk.E != testPrivKey.PublicKey.E {
		t.Errorf("got %d, want %d", ek.vk.E, testPrivKey.PublicKey.E)
	} else if !bytes.Equal(ek.encwk, []byte(str)) {
		t.Errorf("got %v, want %v", ek.encwk, str)
		t.Errorf("got len %d, want len %d", len(ek.encwk), len(str))
	}
}
