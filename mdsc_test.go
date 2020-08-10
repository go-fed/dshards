package dshards

import (
	"bytes"
	"testing"
)

type test struct {
	name           string
	mdsc           string
	accessLevel    accessLevel
	suite          Suite
	keyDataHash    []byte
	keyDataSymmKey SymmetricKey
	nVersion       int
	hashVersion    []byte
	readKey        SymmetricKey
	writeKey       SymmetricKey
}

var tests = []test{
	{
		name:           "verify only mdsc",
		mdsc:           "mdsc:v.0p.gl6qBg6i3dc5dz9cylxPcxIWn4SgLdTxWFzyqtwIljk.6B4Vy69Z6GnqF3VAk8eZkUBZbXgR5tWWoC1C_6Pbe7g",
		accessLevel:    verifyAL,
		suite:          PROTO_ZERO_SUITE,
		keyDataHash:    []byte{130, 94, 170, 6, 14, 162, 221, 215, 57, 119, 63, 92, 202, 92, 79, 115, 18, 22, 159, 132, 160, 45, 212, 241, 88, 92, 242, 170, 220, 8, 150, 57},
		keyDataSymmKey: []byte{232, 30, 21, 203, 175, 89, 232, 105, 234, 23, 117, 64, 147, 199, 153, 145, 64, 89, 109, 120, 17, 230, 213, 150, 160, 45, 66, 255, 163, 219, 123, 184},
		nVersion:       noVersionProvided,
	},
	{
		name:           "read only mdsc",
		mdsc:           "mdsc:r.0p.gl6qBg6i3dc5dz9cylxPcxIWn4SgLdTxWFzyqtwIljk.6B4Vy69Z6GnqF3VAk8eZkUBZbXgR5tWWoC1C_6Pbe7g.wtNehlhYRxooG1un7cLBDMvjs2S-uEz1jLFgfDEH3Cs",
		accessLevel:    readAL,
		suite:          PROTO_ZERO_SUITE,
		keyDataHash:    []byte{130, 94, 170, 6, 14, 162, 221, 215, 57, 119, 63, 92, 202, 92, 79, 115, 18, 22, 159, 132, 160, 45, 212, 241, 88, 92, 242, 170, 220, 8, 150, 57},
		keyDataSymmKey: []byte{232, 30, 21, 203, 175, 89, 232, 105, 234, 23, 117, 64, 147, 199, 153, 145, 64, 89, 109, 120, 17, 230, 213, 150, 160, 45, 66, 255, 163, 219, 123, 184},
		nVersion:       noVersionProvided,
		readKey:        []byte{194, 211, 94, 134, 88, 88, 71, 26, 40, 27, 91, 167, 237, 194, 193, 12, 203, 227, 179, 100, 190, 184, 76, 245, 140, 177, 96, 124, 49, 7, 220, 43},
	},
	{
		name:           "read only mdsc - revision 1 (trailing slash)",
		mdsc:           "mdsc:r.0p.gl6qBg6i3dc5dz9cylxPcxIWn4SgLdTxWFzyqtwIljk.6B4Vy69Z6GnqF3VAk8eZkUBZbXgR5tWWoC1C_6Pbe7g.wtNehlhYRxooG1un7cLBDMvjs2S-uEz1jLFgfDEH3Cs/1/",
		accessLevel:    readAL,
		suite:          PROTO_ZERO_SUITE,
		keyDataHash:    []byte{130, 94, 170, 6, 14, 162, 221, 215, 57, 119, 63, 92, 202, 92, 79, 115, 18, 22, 159, 132, 160, 45, 212, 241, 88, 92, 242, 170, 220, 8, 150, 57},
		keyDataSymmKey: []byte{232, 30, 21, 203, 175, 89, 232, 105, 234, 23, 117, 64, 147, 199, 153, 145, 64, 89, 109, 120, 17, 230, 213, 150, 160, 45, 66, 255, 163, 219, 123, 184},
		nVersion:       1,
		readKey:        []byte{194, 211, 94, 134, 88, 88, 71, 26, 40, 27, 91, 167, 237, 194, 193, 12, 203, 227, 179, 100, 190, 184, 76, 245, 140, 177, 96, 124, 49, 7, 220, 43},
	},
	{
		name:           "read only mdsc - revision 1 w/ hash",
		mdsc:           "mdsc:r.0p.gl6qBg6i3dc5dz9cylxPcxIWn4SgLdTxWFzyqtwIljk.6B4Vy69Z6GnqF3VAk8eZkUBZbXgR5tWWoC1C_6Pbe7g.wtNehlhYRxooG1un7cLBDMvjs2S-uEz1jLFgfDEH3Cs/1/bNIYWl3VtH5e3m0Znp80fU5qtH6IvqpGl3GlyXmNoD0",
		accessLevel:    readAL,
		suite:          PROTO_ZERO_SUITE,
		keyDataHash:    []byte{130, 94, 170, 6, 14, 162, 221, 215, 57, 119, 63, 92, 202, 92, 79, 115, 18, 22, 159, 132, 160, 45, 212, 241, 88, 92, 242, 170, 220, 8, 150, 57},
		keyDataSymmKey: []byte{232, 30, 21, 203, 175, 89, 232, 105, 234, 23, 117, 64, 147, 199, 153, 145, 64, 89, 109, 120, 17, 230, 213, 150, 160, 45, 66, 255, 163, 219, 123, 184},
		nVersion:       1,
		hashVersion:    []byte{108, 210, 24, 90, 93, 213, 180, 126, 94, 222, 109, 25, 158, 159, 52, 125, 78, 106, 180, 126, 136, 190, 170, 70, 151, 113, 165, 201, 121, 141, 160, 61},
		readKey:        []byte{194, 211, 94, 134, 88, 88, 71, 26, 40, 27, 91, 167, 237, 194, 193, 12, 203, 227, 179, 100, 190, 184, 76, 245, 140, 177, 96, 124, 49, 7, 220, 43},
	},
	{
		name:           "read write mdsc",
		mdsc:           "mdsc:w.0p.gl6qBg6i3dc5dz9cylxPcxIWn4SgLdTxWFzyqtwIljk.6B4Vy69Z6GnqF3VAk8eZkUBZbXgR5tWWoC1C_6Pbe7g.MeMgmy_j0CI8jwT0EUX01bF7N0UAVSYwHhNQ67h2WAE",
		accessLevel:    writeAL,
		suite:          PROTO_ZERO_SUITE,
		keyDataHash:    []byte{130, 94, 170, 6, 14, 162, 221, 215, 57, 119, 63, 92, 202, 92, 79, 115, 18, 22, 159, 132, 160, 45, 212, 241, 88, 92, 242, 170, 220, 8, 150, 57},
		keyDataSymmKey: []byte{232, 30, 21, 203, 175, 89, 232, 105, 234, 23, 117, 64, 147, 199, 153, 145, 64, 89, 109, 120, 17, 230, 213, 150, 160, 45, 66, 255, 163, 219, 123, 184},
		nVersion:       noVersionProvided,
		writeKey:       []byte{49, 227, 32, 155, 47, 227, 208, 34, 60, 143, 4, 244, 17, 69, 244, 213, 177, 123, 55, 69, 0, 85, 38, 48, 30, 19, 80, 235, 184, 118, 88, 1},
	},
}

func testVerifyCap(t *testing.T, v verifyMDSC, test test) {
	if v.a != test.accessLevel {
		t.Errorf("got %q, want %q", v.a, test.accessLevel)
	} else if v.s != test.suite {
		t.Errorf("got %q, want %q", v.s, test.suite)
	} else if !bytes.Equal(v.keyDataHash, test.keyDataHash) {
		t.Errorf("got %v, want %v", v.keyDataHash, test.keyDataHash)
		t.Errorf("got len %d, want len %d", len(v.keyDataHash), len(test.keyDataHash))
	} else if !bytes.Equal(v.keyDataSymmKey, test.keyDataSymmKey) {
		t.Errorf("got %v, want %v", v.keyDataSymmKey, test.keyDataSymmKey)
		t.Errorf("got len %d, want len %d", len(v.keyDataSymmKey), len(test.keyDataSymmKey))
	} else if v.nVersion != test.nVersion {
		t.Errorf("got %d, want %d", v.nVersion, test.nVersion)
	} else if !bytes.Equal(v.hashVersion, test.hashVersion) {
		t.Errorf("got %v, want %v", v.hashVersion, test.hashVersion)
		t.Errorf("got len %d, want len %d", len(v.hashVersion), len(test.hashVersion))
	}
}

func testReadCap(t *testing.T, v *readMDSC, test test) {
	testVerifyCap(t, v.verifyMDSC, test)
	if !bytes.Equal(v.readKey, test.readKey) {
		t.Errorf("got %v, want %v", v.readKey, test.readKey)
		t.Errorf("got len %d, want len %d", len(v.readKey), len(test.readKey))
	}
}

func testReadWriteCap(t *testing.T, v *mdsc, test test) {
	testVerifyCap(t, v.verifyMDSC, test)
	if !bytes.Equal(v.writeKey, test.writeKey) {
		t.Errorf("got %v, want %v", v.writeKey, test.writeKey)
		t.Errorf("got len %d, want len %d", len(v.writeKey), len(test.writeKey))
	}
}

func TestParseMDSC(t *testing.T) {
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, err := ParseMDSC(test.mdsc)
			if err != nil {
				t.Errorf("got error: %s", err)
			}
			switch test.accessLevel {
			case verifyAL:
				if _, ok := c.(VerifyCap); !ok {
					t.Errorf("got unexpected type: %T", c)
				} else if v, ok := c.(*verifyMDSC); !ok {
					t.Errorf("got unexpected type: %T", c)
				} else {
					testVerifyCap(t, *v, test)
				}
			case readAL:
				if _, ok := c.(ReadCap); !ok {
					t.Errorf("got unexpected type: %T", c)
				} else if r, ok := c.(*readMDSC); !ok {
					t.Errorf("got unexpected type: %T", c)
				} else {
					testReadCap(t, r, test)
				}
			case writeAL:
				if _, ok := c.(ReadWriteCap); !ok {
					t.Errorf("got unexpected type: %T", c)
				} else if m, ok := c.(*mdsc); !ok {
					t.Errorf("got unexpected type: %T", c)
				} else {
					testReadWriteCap(t, m, test)
				}
			default:
				t.Errorf("test uses unknown access level: %s", test.accessLevel)
			}
		})
	}
}

func TestParseMDSCReString(t *testing.T) {
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, err := ParseMDSC(test.mdsc)
			if err != nil {
				t.Errorf("got error: %s", err)
			}
			m := c.String()
			if m != test.mdsc {
				t.Errorf("got %q, want %q", m, test.mdsc)
				t.Errorf("got len %d, want len %d", len(m), len(test.mdsc))
			}
		})
	}

}
