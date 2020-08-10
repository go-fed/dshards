package dshards

import (
	"reflect"
	"testing"
)

var (
	revSigBytes1 []byte   = []byte("[7\"history[[7\"rev-sig[8\"revisioni0e2:123:333]4:sig1][7\"rev-sig[8\"revisioni1e4:12345:11111]4:sig2]]]")
	revSig1      []RevSig = []RevSig{
		{
			rev: Revision{
				n:      0,
				iv:     []byte{49, 50},
				encLoc: []byte{51, 51, 51},
			},
			sig: []byte("sig1"),
		},
		{
			rev: Revision{
				n:      1,
				iv:     []byte{49, 50, 51, 52},
				encLoc: []byte{49, 49, 49, 49, 49},
			},
			sig: []byte("sig2"),
		},
	}
	revSigBytes2 []byte   = []byte("[7\"history[[7\"rev-sig[8\"revisioni0e2:123:333]4:sig1][7\"rev-sig[8\"revisioni1e4:12345:11111]4:sig2][7\"rev-sig[8\"revisioni2e7:12344448:11111111]10:signature3]]]")
	revSig2      []RevSig = []RevSig{
		{
			rev: Revision{
				n:      0,
				iv:     []byte{49, 50},
				encLoc: []byte{51, 51, 51},
			},
			sig: []byte("sig1"),
		},
		{
			rev: Revision{
				n:      1,
				iv:     []byte{49, 50, 51, 52},
				encLoc: []byte{49, 49, 49, 49, 49},
			},
			sig: []byte("sig2"),
		},
		{
			rev: Revision{
				n:      2,
				iv:     []byte{49, 50, 51, 52, 52, 52, 52},
				encLoc: []byte{49, 49, 49, 49, 49, 49, 49, 49},
			},
			sig: []byte("signature3"),
		},
	}
	dynLoc1    string   = "urn:sha256d:7gfqd3hDTf56FEb9i_x9_cxwgVwjUNDwldJtC9v1T8o"
	dynLoc2    string   = "urn:sha256d:fwFIj8TIXaeiViqbH252V5L0mY3EOb5pPXhQg-Xci1c"
	dynLoc3    string   = "urn:sha256d:E7XwTkJO2ufGW7cCc9qk5rNJPh2xTbxxDN0HMQHiP4s"
	revSigDyn1 []RevSig = []RevSig{
		{
			rev: Revision{
				n:      0,
				iv:     []byte{49, 50},
				encLoc: []byte(dynLoc1),
			},
		},
		{
			rev: Revision{
				n:      1,
				iv:     []byte{49, 50, 51, 52},
				encLoc: []byte(dynLoc2),
			},
		},
		{
			rev: Revision{
				n:      2,
				iv:     []byte{49, 50, 51, 52, 52, 52, 52},
				encLoc: []byte(dynLoc3),
			},
		},
	}
)

type unmarshaler interface {
	Unmarshal(b []byte) error
}

func getRevSigs(t *testing.T, u unmarshaler) []RevSig {
	var got []RevSig
	switch v := u.(type) {
	case *HistoryVerifyOnly:
		got = v.revsigs
	case *HistoryReadOnly:
		got = v.revsigs
	case *History:
		got = v.revsigs
	default:
		t.Errorf("test unknown type: %T", u)
	}
	return got
}

type marshaler interface {
	Marshal() ([]byte, error)
}

type verifier interface {
	Verify(i int) error
}

type lener interface {
	Len() int
}

type reader interface {
	ReadURN(i int) (URN, error)
}

func TestUnmarshal(t *testing.T) {
	tests := []struct {
		name   string
		in     []byte
		u      unmarshaler
		expect []RevSig
	}{
		{
			name:   "Empty",
			in:     []byte("[7\"history]"),
			u:      &HistoryVerifyOnly{},
			expect: nil,
		},
		{
			name:   "VerifyOnly",
			in:     revSigBytes1,
			u:      &HistoryVerifyOnly{},
			expect: revSig1,
		},
		{
			name:   "ReadOnly",
			in:     revSigBytes1,
			u:      &HistoryReadOnly{},
			expect: revSig1,
		},
		{
			name:   "History",
			in:     revSigBytes1,
			u:      &History{},
			expect: revSig1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.u.Unmarshal(test.in)
			if err != nil {
				t.Errorf("got error: %s", err)
			}
			got := getRevSigs(t, test.u)
			if !reflect.DeepEqual(got, test.expect) {
				t.Errorf("got %v, want %v", got, test.expect)
				t.Errorf("got len %d, want len %d", len(got), len(test.expect))
			}
		})
	}
}

func TestMarshal(t *testing.T) {
	tests := []struct {
		name   string
		m      marshaler
		expect []byte
	}{
		{
			name:   "Empty",
			m:      &HistoryVerifyOnly{},
			expect: []byte("[7\"history]"),
		},
		{
			name: "VerifyOnly",
			m: &HistoryVerifyOnly{
				revsigs: revSig1,
			},
			expect: revSigBytes1,
		},
		{
			name: "ReadOnly",
			m: &HistoryReadOnly{
				HistoryVerifyOnly: HistoryVerifyOnly{
					revsigs: revSig1,
				},
			},
			expect: revSigBytes1,
		},
		{
			name: "History",
			m: &History{
				HistoryReadOnly: HistoryReadOnly{
					HistoryVerifyOnly: HistoryVerifyOnly{
						revsigs: revSig1,
					},
				},
			},
			expect: revSigBytes1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b, err := test.m.Marshal()
			if err != nil {
				t.Errorf("got error: %s", err)
			}
			if !reflect.DeepEqual(b, test.expect) {
				t.Errorf("got %s, want %s", b, test.expect)
				t.Errorf("got len %d, want len %d", len(b), len(test.expect))
			}
		})
	}
}

func TestLen(t *testing.T) {
	tests := []struct {
		name   string
		l      lener
		expect int
	}{
		{
			name:   "Empty",
			l:      &HistoryVerifyOnly{},
			expect: 0,
		},
		{
			name: "VerifyOnly",
			l: &HistoryVerifyOnly{
				revsigs: revSig1,
			},
			expect: 2,
		},
		{
			name: "ReadOnly",
			l: &HistoryReadOnly{
				HistoryVerifyOnly: HistoryVerifyOnly{
					revsigs: revSig1,
				},
			},
			expect: 2,
		},
		{
			name: "History",
			l: &History{
				HistoryReadOnly: HistoryReadOnly{
					HistoryVerifyOnly: HistoryVerifyOnly{
						revsigs: revSig1,
					},
				},
			},
			expect: 2,
		},
		{
			name: "VerifyOnly 3",
			l: &HistoryVerifyOnly{
				revsigs: revSig2,
			},
			expect: 3,
		},
		{
			name: "ReadOnly 3",
			l: &HistoryReadOnly{
				HistoryVerifyOnly: HistoryVerifyOnly{
					revsigs: revSig2,
				},
			},
			expect: 3,
		},
		{
			name: "History 3",
			l: &History{
				HistoryReadOnly: HistoryReadOnly{
					HistoryVerifyOnly: HistoryVerifyOnly{
						revsigs: revSig2,
					},
				},
			},
			expect: 3,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			i := test.l.Len()
			if i != test.expect {
				t.Errorf("got %d, want %d", i, test.expect)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name   string
		v      verifier
		i      int
		expect error
	}{
		{
			name: "Verify-Only: Verify Head",
			v: &HistoryVerifyOnly{
				revsigs: revSigDyn1,
				p:       EncryptedKeyData{vk: testPrivKey.PublicKey},
				s:       PROTO_ZERO_SUITE,
			},
			i: 0,
		},
		{
			name: "Verify-Only: Verify Middle",
			v: &HistoryVerifyOnly{
				revsigs: revSigDyn1,
				p:       EncryptedKeyData{vk: testPrivKey.PublicKey},
				s:       PROTO_ZERO_SUITE,
			},
			i: 1,
		},
		{
			name: "Verify-Only: Verify Tail",
			v: &HistoryVerifyOnly{
				revsigs: revSigDyn1,
				p:       EncryptedKeyData{vk: testPrivKey.PublicKey},
				s:       PROTO_ZERO_SUITE,
			},
			i: 2,
		},
		{
			name: "Read-Only: Verify Head",
			v: &HistoryReadOnly{
				HistoryVerifyOnly: HistoryVerifyOnly{
					revsigs: revSigDyn1,
					p:       EncryptedKeyData{vk: testPrivKey.PublicKey},
					s:       PROTO_ZERO_SUITE,
				},
			},
			i: 0,
		},
		{
			name: "Read-Only: Verify Middle",
			v: &HistoryReadOnly{
				HistoryVerifyOnly: HistoryVerifyOnly{
					revsigs: revSigDyn1,
					p:       EncryptedKeyData{vk: testPrivKey.PublicKey},
					s:       PROTO_ZERO_SUITE,
				},
			},
			i: 1,
		},
		{
			name: "Read-Only: Verify Tail",
			v: &HistoryReadOnly{
				HistoryVerifyOnly: HistoryVerifyOnly{
					revsigs: revSigDyn1,
					p:       EncryptedKeyData{vk: testPrivKey.PublicKey},
					s:       PROTO_ZERO_SUITE,
				},
			},
			i: 2,
		},
		{
			name: "History: Verify Head",
			v: &History{
				HistoryReadOnly: HistoryReadOnly{
					HistoryVerifyOnly: HistoryVerifyOnly{
						revsigs: revSigDyn1,
						p:       EncryptedKeyData{vk: testPrivKey.PublicKey},
						s:       PROTO_ZERO_SUITE,
					},
				},
			},
			i: 0,
		},
		{
			name: "History: Verify Middle",
			v: &History{
				HistoryReadOnly: HistoryReadOnly{
					HistoryVerifyOnly: HistoryVerifyOnly{
						revsigs: revSigDyn1,
						p:       EncryptedKeyData{vk: testPrivKey.PublicKey},
						s:       PROTO_ZERO_SUITE,
					},
				},
			},
			i: 1,
		},
		{
			name: "History: Verify Tail",
			v: &History{
				HistoryReadOnly: HistoryReadOnly{
					HistoryVerifyOnly: HistoryVerifyOnly{
						revsigs: revSigDyn1,
						p:       EncryptedKeyData{vk: testPrivKey.PublicKey},
						s:       PROTO_ZERO_SUITE,
					},
				},
			},
			i: 2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.v.Verify(test.i)
			if err != test.expect {
				t.Errorf("got error %v, want error %v", err, test.expect)
			}
		})
	}
}

func TestRead(t *testing.T) {
	tests := []struct {
		name   string
		r      reader
		i      int
		expect string
	}{
		{
			name: "Read-Only: Read Head",
			r: &HistoryReadOnly{
				HistoryVerifyOnly: HistoryVerifyOnly{
					revsigs: revSigDyn1,
					s:       PROTO_ZERO_SUITE,
				},
				readKey: testSymmKey,
			},
			i:      0,
			expect: dynLoc1,
		},
		{
			name: "Read-Only: Read Middle",
			r: &HistoryReadOnly{
				HistoryVerifyOnly: HistoryVerifyOnly{
					revsigs: revSigDyn1,
					s:       PROTO_ZERO_SUITE,
				},
				readKey: testSymmKey,
			},
			i:      1,
			expect: dynLoc2,
		},
		{
			name: "Read-Only: Read Tail",
			r: &HistoryReadOnly{
				HistoryVerifyOnly: HistoryVerifyOnly{
					revsigs: revSigDyn1,
					s:       PROTO_ZERO_SUITE,
				},
				readKey: testSymmKey,
			},
			i:      2,
			expect: dynLoc3,
		},
		{
			name: "History: Read Head",
			r: &History{
				HistoryReadOnly: HistoryReadOnly{
					HistoryVerifyOnly: HistoryVerifyOnly{
						revsigs: revSigDyn1,
						s:       PROTO_ZERO_SUITE,
					},
					readKey: testSymmKey,
				},
			},
			i:      0,
			expect: dynLoc1,
		},
		{
			name: "History: Read Middle",
			r: &History{
				HistoryReadOnly: HistoryReadOnly{
					HistoryVerifyOnly: HistoryVerifyOnly{
						revsigs: revSigDyn1,
						s:       PROTO_ZERO_SUITE,
					},
					readKey: testSymmKey,
				},
			},
			i:      1,
			expect: dynLoc2,
		},
		{
			name: "History: Read Tail",
			r: &History{
				HistoryReadOnly: HistoryReadOnly{
					HistoryVerifyOnly: HistoryVerifyOnly{
						revsigs: revSigDyn1,
						s:       PROTO_ZERO_SUITE,
					},
					readKey: testSymmKey,
				},
			},
			i:      2,
			expect: dynLoc3,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			urn, err := test.r.ReadURN(test.i)
			if err != nil {
				t.Errorf("got error %s", err)
			} else if urn.String() != test.expect {
				t.Errorf("got %s, want %s", urn.String(), test.expect)
			}
		})
	}
}

func TestWrite(t *testing.T) {
	tests := []struct {
		name      string
		h         *History
		p         PublicShard
		expectLen int
		expectURN string
	}{
		{
			name: "History: Write Empty",
			h: &History{
				HistoryReadOnly: HistoryReadOnly{
					HistoryVerifyOnly: HistoryVerifyOnly{
						p: &DecryptedKeyData{vk: testPrivKey.PublicKey},
						s: PROTO_ZERO_SUITE,
					},
					readKey: testSymmKey,
				},
				priv: &DecryptedKeyData{
					vk: testPrivKey.PublicKey,
					wk: testPrivKey,
				},
			},
			p: PublicShard{
				Address: URN{
					dhash: SHA256D,
					hash:  []byte{95, 190, 20, 109, 77, 205, 160, 180, 192, 252, 219, 169, 139, 192, 225, 104, 159, 232, 66, 148, 61, 228, 161, 110, 144, 192, 36, 36, 154, 45, 42, 10},
				},
			},
			expectLen: 1,
			expectURN: "urn:sha256d:X74UbU3NoLTA_Nupi8DhaJ_oQpQ95KFukMAkJJotKgo",
		},
		{
			name: "History: Write Third",
			h: &History{
				HistoryReadOnly: HistoryReadOnly{
					HistoryVerifyOnly: HistoryVerifyOnly{
						revsigs: revSig1,
						p:       &DecryptedKeyData{vk: testPrivKey.PublicKey},
						s:       PROTO_ZERO_SUITE,
					},
					readKey: testSymmKey,
				},
				priv: &DecryptedKeyData{
					vk: testPrivKey.PublicKey,
					wk: testPrivKey,
				},
			},
			p: PublicShard{
				Address: URN{
					dhash: SHA256D,
					hash:  []byte{95, 190, 20, 109, 77, 205, 160, 180, 192, 252, 219, 169, 139, 192, 225, 104, 159, 232, 66, 148, 61, 228, 161, 110, 144, 192, 36, 36, 154, 45, 42, 10},
				},
			},
			expectLen: 3,
			expectURN: "urn:sha256d:X74UbU3NoLTA_Nupi8DhaJ_oQpQ95KFukMAkJJotKgo",
		},
		{
			name: "History: Write Fourth",
			h: &History{
				HistoryReadOnly: HistoryReadOnly{
					HistoryVerifyOnly: HistoryVerifyOnly{
						revsigs: revSig2,
						p:       &DecryptedKeyData{vk: testPrivKey.PublicKey},
						s:       PROTO_ZERO_SUITE,
					},
					readKey: testSymmKey,
				},
				priv: &DecryptedKeyData{
					vk: testPrivKey.PublicKey,
					wk: testPrivKey,
				},
			},
			p: PublicShard{
				Address: URN{
					dhash: SHA256D,
					hash:  []byte{95, 190, 20, 109, 77, 205, 160, 180, 192, 252, 219, 169, 139, 192, 225, 104, 159, 232, 66, 148, 61, 228, 161, 110, 144, 192, 36, 36, 154, 45, 42, 10},
				},
			},
			expectLen: 4,
			expectURN: "urn:sha256d:X74UbU3NoLTA_Nupi8DhaJ_oQpQ95KFukMAkJJotKgo",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.h.Write(test.p)
			if err != nil {
				t.Errorf("got error %s", err)
			} else if gotLen := test.h.Len(); gotLen != test.expectLen {
				t.Errorf("got len %d, want len %d", gotLen, test.expectLen)
			} else if gotVerErr := test.h.Verify(test.expectLen - 1); gotVerErr != nil {
				t.Errorf("got verification error %s", gotVerErr)
			} else if gotURN, err := test.h.ReadURN(test.expectLen - 1); err != nil {
				t.Errorf("got readURN error %s", err)
			} else if gotURN.String() != test.expectURN {
				t.Errorf("got %s, want %s", gotURN, test.expectURN)
			}
		})
	}
}

func TestUnmarshalWriteMarshal(t *testing.T) {
	tests := []struct {
		name        string
		in          []byte
		h           *History
		p           PublicShard
		expectBytes []byte
	}{
		{
			name: "History: Write Third",
			in:   revSigBytes1,
			h: &History{
				HistoryReadOnly: HistoryReadOnly{
					HistoryVerifyOnly: HistoryVerifyOnly{
						p: &DecryptedKeyData{vk: testPrivKey.PublicKey},
						s: PROTO_ZERO_SUITE,
					},
					readKey: testSymmKey,
				},
				priv: &DecryptedKeyData{
					vk: testPrivKey.PublicKey,
					wk: testPrivKey,
				},
			},
			p: PublicShard{
				Address: URN{
					dhash: SHA256D,
					hash:  []byte{95, 190, 20, 109, 77, 205, 160, 180, 192, 252, 219, 169, 139, 192, 225, 104, 159, 232, 66, 148, 61, 228, 161, 110, 144, 192, 36, 36, 154, 45, 42, 10},
				},
			},
			expectBytes: []byte{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.h.Unmarshal(test.in)
			if err != nil {
				t.Errorf("got unmarshal error %s", err)
				return
			}
			err = test.h.Write(test.p)
			if err != nil {
				t.Errorf("got write error %s", err)
				return
			}
			got, err := test.h.Marshal()
			if err != nil {
				t.Errorf("got write error %s", err)
			}
			t.Logf("marshal-after-write: %s", got)
		})
	}
}
