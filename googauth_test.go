package dgoogauth

import (
	"testing"
)

var codeTests = []struct {
	secret string
	value  int64
	code   int
}{
	// from http://code.google.com/p/google-authenticator/source/browse/libpam/pam_google_authenticator_unittest.c
	{"2SH3V3GDW7ZNMGYE", 1, 293240},
	{"2SH3V3GDW7ZNMGYE", 5, 932068},
	{"2SH3V3GDW7ZNMGYE", 10000, 50548},
}

func TestCode(t *testing.T) {

	for _, v := range codeTests {
		c := ComputeCode(v.secret, v.value)

		if c != v.code {
			t.Errorf("computeCode(%s, %d): got %d expected %d\n", v.secret, v.value, c, v.code)
		}

	}
}

func TestScratchCode(t *testing.T) {

	var cotp OTPConfig

	cotp.ScratchCodes = []int{11112222, 22223333}

	var scratchTests = []struct {
		code   int
		result bool
	}{
		{33334444, false},
		{11112222, true},
		{11112222, false},
		{22223333, true},
		{22223333, false},
		{33334444, false},
	}

	for _, s := range scratchTests {
		r, e := cotp.checkScratchCodes(s.code)
		if r != s.result {
			t.Errorf("scratchcode(%s) failed: got %s expected %s", s.code, r, s.result)
		}
		if e != nil {
			t.Errorf("weird error from scratchcode(%s): got %s", s.code, e)
		}
	}
}
