package rorwk

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"unicode/utf16"

	"github.com/pkg/errors"
)

// HashAPI32 is used to calculate Windows API hash for 32 bit.
func HashAPI32(module, procedure string) ([]byte, []byte, []byte, error) {
	key, err := generateKey()
	if err != nil {
		return nil, nil, nil, err
	}
	key = key[:4]
	mHash, pHash, err := HashAPI32WithKey(module, procedure, key)
	if err != nil {
		return nil, nil, nil, err
	}
	return mHash, pHash, key, nil
}

// HashAPI64 is used to calculate Windows API hash for 64 bit.
func HashAPI64(module, procedure string) ([]byte, []byte, []byte, error) {
	key, err := generateKey()
	if err != nil {
		return nil, nil, nil, err
	}
	key = key[:8]
	mHash, pHash, err := HashAPI64WithKey(module, procedure, key)
	if err != nil {
		return nil, nil, nil, err
	}
	return mHash, pHash, key, nil
}

// HashAPI32WithKey is used to calculate Windows API hash for 32 bit with specific key.
func HashAPI32WithKey(module, procedure string, key []byte) ([]byte, []byte, error) {
	if len(key) != 4 {
		return nil, nil, errors.New("invalid hash api key size")
	}
	const (
		rorBits = 4
		rorSeed = rorBits + 1
		rorKey  = rorBits + 2
		rorMod  = rorBits + 3
		rorProc = rorBits + 4
	)
	var (
		seedHash uint32
		keyHash  uint32
		modHash  uint32
		procHash uint32
	)
	seedHash = binary.LittleEndian.Uint32(key)
	for _, b := range key {
		seedHash = ror32(seedHash, rorSeed)
		seedHash += uint32(b)
	}
	keyHash = seedHash
	for _, b := range key {
		keyHash = ror32(keyHash, rorKey)
		keyHash += uint32(b)
	}
	modHash = seedHash
	for _, c := range utf16.Encode([]rune(module)) {
		buf := make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, c)
		b0 := buf[0]
		b1 := buf[1]
		if b0 >= 'a' {
			b0 -= 0x20
		}
		if b1 >= 'a' {
			b1 -= 0x20
		}
		modHash = ror32(modHash, rorMod)
		modHash += uint32(b0)
		modHash = ror32(modHash, rorMod)
		modHash += uint32(b1)
	}
	modHash += seedHash + keyHash
	procHash = seedHash
	for _, c := range procedure {
		procHash = ror32(procHash, rorProc)
		procHash += uint32(c)
	}
	procHash += seedHash + keyHash
	mHash := make([]byte, 4)
	binary.LittleEndian.PutUint32(mHash, modHash)
	pHash := make([]byte, 4)
	binary.LittleEndian.PutUint32(pHash, procHash)
	return mHash, pHash, nil
}

// HashAPI64WithKey is used to calculate Windows API hash for 64 bit with specific key.
func HashAPI64WithKey(module, procedure string, key []byte) ([]byte, []byte, error) {
	if len(key) != 8 {
		return nil, nil, errors.New("invalid hash api key size")
	}
	const (
		rorBits = 8
		rorSeed = rorBits + 1
		rorKey  = rorBits + 2
		rorMod  = rorBits + 3
		rorProc = rorBits + 4
	)
	var (
		seedHash uint64
		keyHash  uint64
		modHash  uint64
		procHash uint64
	)
	seedHash = binary.LittleEndian.Uint64(key)
	for _, b := range key {
		seedHash = ror64(seedHash, rorSeed)
		seedHash += uint64(b)
	}
	keyHash = seedHash
	for _, b := range key {
		keyHash = ror64(keyHash, rorKey)
		keyHash += uint64(b)
	}
	modHash = seedHash
	for _, c := range utf16.Encode([]rune(module)) {
		buf := make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, c)
		b0 := buf[0]
		b1 := buf[1]
		if b0 >= 'a' {
			b0 -= 0x20
		}
		if b1 >= 'a' {
			b1 -= 0x20
		}
		modHash = ror64(modHash, rorMod)
		modHash += uint64(b0)
		modHash = ror64(modHash, rorMod)
		modHash += uint64(b1)
	}
	modHash += seedHash + keyHash
	procHash = seedHash
	for _, c := range procedure {
		procHash = ror64(procHash, rorProc)
		procHash += uint64(c)
	}
	procHash += seedHash + keyHash
	mHash := make([]byte, 8)
	binary.LittleEndian.PutUint64(mHash, modHash)
	pHash := make([]byte, 8)
	binary.LittleEndian.PutUint64(pHash, procHash)
	return mHash, pHash, nil
}

// BytesToUint64 is used to convert hash or key bytes to uint64.
// It used to convert result to arguments for syscall.SyscallN.
func BytesToUint64(b []byte) uint64 {
	var val uint64
	switch len(b) {
	case 4:
		val = uint64(binary.LittleEndian.Uint32(b))
	case 8:
		val = binary.LittleEndian.Uint64(b)
	}
	return val
}

func generateKey() ([]byte, error) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate random key")
	}
	hash := sha256.Sum256(key)
	return hash[:], nil
}

func ror32(value, bits uint32) uint32 {
	return value>>bits | value<<(32-bits)
}

func ror64(value, bits uint64) uint64 {
	return value>>bits | value<<(64-bits)
}
