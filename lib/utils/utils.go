package lib

import "math/rand"

const letterBytes = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// RandStringBytes generated a random string
func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
