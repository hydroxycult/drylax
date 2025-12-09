package util

import (
	"crypto/rand"
	"github.com/pkg/errors"
	"math/big"
)

const base62Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func GenID(exists func(string) (bool, error)) (string, error) {
	for retry := 0; retry < 5; retry++ {
		buf := make([]byte, 8)
		if _, err := rand.Read(buf); err != nil {
			return "", errors.Wrap(err, "rand fail")
		}
		num := new(big.Int).SetBytes(buf)
		id := toBase62(num)
		exist, err := exists(id)
		if err != nil {
			return "", err
		}
		if !exist {
			return id, nil
		}
	}
	return "", errors.New("id collision after 5 retries")
}
func toBase62(num *big.Int) string {
	if num.Sign() == 0 {
		return string(base62Chars[0])
	}
	base := big.NewInt(62)
	result := make([]byte, 0, 11)
	zero := big.NewInt(0)
	temp := new(big.Int).Set(num)
	for temp.Cmp(zero) > 0 {
		mod := new(big.Int)
		temp.DivMod(temp, base, mod)
		result = append(result, base62Chars[mod.Int64()])
	}
	for len(result) < 11 {
		result = append(result, base62Chars[0])
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return string(result)
}
