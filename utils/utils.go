package utils

import (
	"fmt"
	"math/rand"
)

const alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func RandomString(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = alphanumeric[rand.Intn(len(alphanumeric))]
	}
	return string(b)
}

func UNCPath(host string, share string, extra ...string) string {
	path := fmt.Sprintf(`\\%s\%s`, host, share)
	for _, part := range extra {
		path += `\` + part
	}
	return path
}
