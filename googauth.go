package dgoogauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
)

func computeCode(secret string, value uint64) int {

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
