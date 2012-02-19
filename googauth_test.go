package dgoogauth

import (
	"testing"
)

var codeTests = []struct {
	secret string
	value  uint64
	code   int
}{
	// from http://code.google.com/p/google-authenticator/source/browse/libpam/pam_google_authenticator_unittest.c
	{"2SH3V3GDW7ZNMGYE", 1, 293240},
	{"2SH3V3GDW7ZNMGYE", 5, 932068},
	{"2SH3V3GDW7ZNMGYE", 10000, 50548},
}

func TestCode(t *testing.T) {

	for _, v := range codeTests {
		c := computeCode(v.secret, v.value)

		if c != v.code {
			t.Errorf("computeCode(%s, %d): got %d expected %d\n", v.secret, v.value, c, v.code)
		}

	}
}
