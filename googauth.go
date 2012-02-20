/*

Dgoogauth is a Go implementation of the one-time password algorithms supported
by the Google Authenticator project.


*/
package dgoogauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"sort"
	"strconv"
	"time"
)

// ComputeCode computes the response code for a 64-bit challenge 'value' using the secret 'secret'
func ComputeCode(secret string, value uint64) int {

	key, _ := base32.StdEncoding.DecodeString(secret)

	hash := hmac.New(sha1.New, key)
	binary.Write(hash, binary.BigEndian, value)
	h := hash.Sum(nil)

	offset := h[19] & 0x0f

	truncated := binary.BigEndian.Uint32(h[offset : offset+4])

	truncated &= 0x7fffffff
	code := truncated % 1000000

	return int(code)
}

type ErrInvalidCode int

func (ErrInvalidCode) Error() string {
	return "dgoogauth: invalid code"
}

type OTPAuthType int

const (
	AuthFail OTPAuthType = iota
	AuthScratch
	AuthHotp
	AuthTotp
)

type OTPConfig struct {
	Secret        string
	WindowSize    int   // valid range: 0..100 or so
	HotpCounter   int   // 0  == use timestamp
	DisallowReuse []int // timestamps
	ScratchCodes  []int
}

// FIXME: to faciliate unit testing, this function needs to be split up
func (c *OTPConfig) Authenticate(password string) (OTPAuthType, error) {

	var scratch bool

	switch {
	case len(password) == 6 && password[0] >= '0' && password[0] <= '9':
		break
	case len(password) == 8 && password[0] >= '1' && password[0] <= '9':
		scratch = true
		break
	default:
		return AuthFail, ErrInvalidCode(0)
	}

	code, err := strconv.Atoi(password)

	if err != nil {
		return AuthFail, ErrInvalidCode(0)
	}

	if scratch {
		for i, v := range c.ScratchCodes {
			if code == v {
				// remove this code from the list of valid ones
				l := len(c.ScratchCodes) - 1
				c.ScratchCodes[i] = c.ScratchCodes[l] // copy last element over this element
				c.ScratchCodes = c.ScratchCodes[0:l]  // and trim the list length by 1
				return AuthScratch, nil
			}
		}
		return AuthFail, nil
	}

	// we have a counter value we can use
	if c.HotpCounter > 0 {
		for i := 0; i < c.WindowSize; i++ {
			if ComputeCode(c.Secret, uint64(c.HotpCounter+i)) == code {
				c.HotpCounter += i + 1
				// We don't check for overflow here, which means you can only authenticate 2^63 times
				// After that, the counter is negative and the above 'if' test will fail.
				// This matches the behaviour of the PAM module.
				return AuthHotp, nil
			}
		}
		// we must always advance the counter if we tried to authenticate with it
		c.HotpCounter++
		return AuthFail, nil
	}

	// assume we're on Time-basd OTP

        // FIXME: needs to be split up so we can inject a time to test with
	t0 := int(time.Now().Unix() / 30)

	// FIXME: verify conditions are correct w/r/t valid window sizes
	minT := t0 - (c.WindowSize / 2)
	maxT := t0 + (c.WindowSize / 2)
	for t := minT; t <= maxT; t++ {
		if ComputeCode(c.Secret, uint64(t)) == code {

			if c.DisallowReuse != nil {
				for _, timeCode := range c.DisallowReuse {
					if timeCode == t {
						return AuthFail, nil
					}
				}

				// code hasn't been used before
				c.DisallowReuse = append(c.DisallowReuse, t)

				// remove all time codes outside of the valid window
				sort.Ints(c.DisallowReuse)
				min := 0
				for c.DisallowReuse[min] < minT {
					min++
				}
				// FIXME: check we don't have an off-by-one error here
				c.DisallowReuse = c.DisallowReuse[min:]
			}

			return AuthTotp, nil
		}
	}

	return AuthFail, nil
}
