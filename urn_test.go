package dshards

import (
	"bytes"
	"testing"
)

func TestParseURN(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectDHash Hash
		expectHash  []byte
	}{
		{
			name:        "Intro Example",
			input:       "urn:sha256d:X74UbU3NoLTA_Nupi8DhaJ_oQpQ95KFukMAkJJotKgo",
			expectDHash: SHA256D,
			expectHash:  []byte{95, 190, 20, 109, 77, 205, 160, 180, 192, 252, 219, 169, 139, 192, 225, 104, 159, 232, 66, 148, 61, 228, 161, 110, 144, 192, 36, 36, 154, 45, 42, 10},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualURN, err := ParseURN(test.input)
			if err != nil {
				t.Errorf("got error: %s", err)
			} else if actualURN.dhash != test.expectDHash {
				t.Errorf("got %q, want %q", actualURN.dhash, test.expectDHash)
			} else if !bytes.Equal(actualURN.hash, test.expectHash) {
				t.Errorf("got %v, want %v", actualURN.hash, test.expectHash)
			}
		})
	}
}

func TestNewURN(t *testing.T) {
	tests := []struct {
		name    string
		h       Hash
		content []byte
		expect  string
	}{
		{
			name:    "Sample",
			h:       SHA256D,
			content: []byte{228, 193, 64, 108, 49, 53, 219, 108, 198, 21, 88, 134, 52, 118, 198, 214, 117, 85, 40, 234, 45, 113, 128, 2, 99, 104, 77, 4, 225, 117, 218, 190, 14, 20, 231, 10, 60},
			expect:  "urn:sha256d:JvaPnGGMmYdJGu8lEPy0JcMpfqQqC12hE42oOLjmx8k",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualURN, err := NewURN(test.h, test.content)
			actual := actualURN.String()
			if err != nil {
				t.Errorf("got error: %s", err)
			} else if actual != test.expect {
				t.Errorf("got %v, want %v", actual, test.expect)
			}
		})
	}
}

func TestURNToString(t *testing.T) {
	tests := []struct {
		name       string
		inputDHash Hash
		inputHash  []byte
		expect     string
	}{
		{
			name:       "Intro Example",
			inputDHash: SHA256D,
			inputHash:  []byte{95, 190, 20, 109, 77, 205, 160, 180, 192, 252, 219, 169, 139, 192, 225, 104, 159, 232, 66, 148, 61, 228, 161, 110, 144, 192, 36, 36, 154, 45, 42, 10},
			expect:     "urn:sha256d:X74UbU3NoLTA_Nupi8DhaJ_oQpQ95KFukMAkJJotKgo",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := URN{test.inputDHash, test.inputHash}
			if actual := s.String(); actual != test.expect {
				t.Errorf("got %q, want %q", actual, test.expect)
			}
		})
	}
}
