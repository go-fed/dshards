package dshards

import (
	"bytes"
	"testing"
)

func TestParseIDSC(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectSuite Suite
		expectHash  []byte
		expectKey   []byte
	}{
		{
			name:        "Intro Example",
			input:       "idsc:0p.X74UbU3NoLTA_Nupi8DhaJ_oQpQ95KFukMAkJJotKgo.eekxqfiZIcEnc8cpR-sD_3X3qLaTzQW-KnovArMkGP0",
			expectSuite: PROTO_ZERO_SUITE,
			expectHash:  []byte{95, 190, 20, 109, 77, 205, 160, 180, 192, 252, 219, 169, 139, 192, 225, 104, 159, 232, 66, 148, 61, 228, 161, 110, 144, 192, 36, 36, 154, 45, 42, 10},
			expectKey:   []byte{121, 233, 49, 169, 248, 153, 33, 193, 39, 115, 199, 41, 71, 235, 3, 255, 117, 247, 168, 182, 147, 205, 5, 190, 42, 122, 47, 2, 179, 36, 24, 253},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualIDSC, err := ParseIDSC(test.input)
			if err != nil {
				t.Errorf("got error: %s", err)
			} else if actualIDSC.s != test.expectSuite {
				t.Errorf("got %q, want %q", actualIDSC.s, test.expectSuite)
			} else if !bytes.Equal(actualIDSC.hash, test.expectHash) {
				t.Errorf("got %v, want %v", actualIDSC.hash, test.expectHash)
			} else if !bytes.Equal(actualIDSC.symmKey, test.expectKey) {
				t.Errorf("got %v, want %v", actualIDSC.symmKey, test.expectKey)
			}
		})
	}
}

func TestNewIDSC(t *testing.T) {
	tests := []struct {
		name    string
		s       Suite
		content []byte
		key     []byte
		expect  string
	}{
		{
			name:    "Sample",
			s:       PROTO_ZERO_SUITE,
			content: []byte{228, 193, 64, 108, 49, 53, 219, 108, 198, 21, 88, 134, 52, 118, 198, 214, 117, 85, 40, 234, 45, 113, 128, 2, 99, 104, 77, 4, 225, 117, 218, 190, 14, 20, 231, 10, 60},
			key:     []byte{121, 233, 49, 169, 248, 153, 33, 193, 39, 115, 199, 41, 71, 235, 3, 255, 117, 247, 168, 182, 147, 205, 5, 190, 42, 122, 47, 2, 179, 36, 24, 253},
			expect:  "idsc:0p.JvaPnGGMmYdJGu8lEPy0JcMpfqQqC12hE42oOLjmx8k.eekxqfiZIcEnc8cpR-sD_3X3qLaTzQW-KnovArMkGP0",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualIDSC, err := NewIDSC(test.s, test.content, test.key)
			actual := actualIDSC.String()
			if err != nil {
				t.Errorf("got error: %s", err)
			} else if actual != test.expect {
				t.Errorf("got %v, want %v", actual, test.expect)
			}
		})
	}
}

func TestIDSCToString(t *testing.T) {
	tests := []struct {
		name         string
		inputSuite   Suite
		inputHash    []byte
		inputSymmKey []byte
		expect       string
	}{
		{
			name:         "Intro Example",
			inputSuite:   PROTO_ZERO_SUITE,
			inputHash:    []byte{95, 190, 20, 109, 77, 205, 160, 180, 192, 252, 219, 169, 139, 192, 225, 104, 159, 232, 66, 148, 61, 228, 161, 110, 144, 192, 36, 36, 154, 45, 42, 10},
			inputSymmKey: []byte{121, 233, 49, 169, 248, 153, 33, 193, 39, 115, 199, 41, 71, 235, 3, 255, 117, 247, 168, 182, 147, 205, 5, 190, 42, 122, 47, 2, 179, 36, 24, 253},
			expect:       "idsc:0p.X74UbU3NoLTA_Nupi8DhaJ_oQpQ95KFukMAkJJotKgo.eekxqfiZIcEnc8cpR-sD_3X3qLaTzQW-KnovArMkGP0",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := IDSC{test.inputSuite, test.inputHash, test.inputSymmKey}
			if actual := s.String(); actual != test.expect {
				t.Errorf("got %q, want %q", actual, test.expect)
			}
		})
	}
}

func TestIDSCToURN(t *testing.T) {
	tests := []struct {
		name         string
		inputSuite   Suite
		inputHash    []byte
		inputSymmKey []byte
		expect       string
	}{
		{
			name:         "Intro Example",
			inputSuite:   PROTO_ZERO_SUITE,
			inputHash:    []byte{95, 190, 20, 109, 77, 205, 160, 180, 192, 252, 219, 169, 139, 192, 225, 104, 159, 232, 66, 148, 61, 228, 161, 110, 144, 192, 36, 36, 154, 45, 42, 10},
			inputSymmKey: []byte{121, 233, 49, 169, 248, 153, 33, 193, 39, 115, 199, 41, 71, 235, 3, 255, 117, 247, 168, 182, 147, 205, 5, 190, 42, 122, 47, 2, 179, 36, 24, 253},
			expect:       "urn:sha256d:X74UbU3NoLTA_Nupi8DhaJ_oQpQ95KFukMAkJJotKgo",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := IDSC{test.inputSuite, test.inputHash, test.inputSymmKey}
			sh, err := s.URN()
			if err != nil {
				t.Errorf("got error: %s", err)
			} else if actual := sh.String(); actual != test.expect {
				t.Errorf("got %q, want %q", actual, test.expect)
			}
		})
	}
}
