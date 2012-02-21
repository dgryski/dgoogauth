package dgoogauth

import (
	"testing"
)

// Test vectors via:
// http://code.google.com/p/google-authenticator/source/browse/libpam/pam_google_authenticator_unittest.c
// https://google-authenticator.googlecode.com/hg/libpam/totp.html

var codeTests = []struct {
	secret string
	value  int64
	code   int
}{
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
			t.Errorf("scratchcode(%s) failed: got %t expected %t", s.code, r, s.result)
		}
		if e != nil {
			t.Errorf("weird error from scratchcode(%s): got %s", s.code, e)
		}
	}
}

func TestHotpCode(t *testing.T) {

	var cotp OTPConfig

	// reuse our test values from above
	// perhaps create more?
	cotp.Secret = "2SH3V3GDW7ZNMGYE"
	cotp.HotpCounter = 1
	cotp.WindowSize = 3

	var counterCodes = []struct {
		code    int
		result  bool
		counter int
	}{
		{ /* 1 */ 293240, true, 2},   // increments on success
		{ /* 1 */ 293240, false, 3},  // and failure
		{ /* 5 */ 932068, true, 6},   // inside of window
		{ /* 10 */ 481725, false, 7}, // outside of window
		{ /* 10 */ 481725, false, 8}, // outside of window
		{ /* 10 */ 481725, true, 11}, // now inside of window
	}

	for i, s := range counterCodes {
		r, e := cotp.checkHotpCode(s.code)
		if r != s.result {
			t.Errorf("counterCode(%d) (step %d) failed: got %t expected %t", s.code, i, r, s.result)
		}
		if cotp.HotpCounter != s.counter {
			t.Errorf("hotpCounter incremented poorly: got %d expected %d", cotp.HotpCounter, s.counter)
		}
		if e != nil {
			t.Errorf("weird error from checkHotpCode(%d): got %s", s.code, e)
		}
	}
}
