package rorwk

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/For-ACGN/monkey"
	"github.com/stretchr/testify/require"
)

func TestHashAPI32(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		mHash, pHash, hKey, err := HashAPI32("kernel32.dll", "WinExec")
		require.NoError(t, err)
		require.Len(t, mHash, 4)
		require.Len(t, pHash, 4)
		require.Len(t, hKey, 4)

		fmt.Println("module hash:   ", mHash)
		fmt.Println("procedure hash:", pHash)
		fmt.Println("hash key:      ", hKey)
	})

	t.Run("failed to generate key", func(t *testing.T) {
		patch := func(b []byte) (n int, err error) {
			return 0, errors.New("monkey error")
		}
		pg := monkey.Patch(rand.Read, patch)
		defer pg.Unpatch()

		mHash, pHash, hKey, err := HashAPI32("kernel32.dll", "WinExec")
		require.ErrorContains(t, err, "monkey error")
		require.Nil(t, mHash)
		require.Nil(t, pHash)
		require.Nil(t, hKey)
	})

	t.Run("invalid key size", func(t *testing.T) {
		patch := func(string, string, []byte) ([]byte, []byte, error) {
			return nil, nil, errors.New("monkey error")
		}
		pg := monkey.Patch(HashAPI32WithKey, patch)
		defer pg.Unpatch()

		mHash, pHash, hKey, err := HashAPI32("kernel32.dll", "WinExec")
		require.ErrorContains(t, err, "monkey error")
		require.Nil(t, mHash)
		require.Nil(t, pHash)
		require.Nil(t, hKey)
	})
}

func TestHashAPI64(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		mHash, pHash, hKey, err := HashAPI64("kernel32.dll", "WinExec")
		require.NoError(t, err)
		require.Len(t, mHash, 8)
		require.Len(t, pHash, 8)
		require.Len(t, hKey, 8)

		fmt.Println("module hash:   ", mHash)
		fmt.Println("procedure hash:", pHash)
		fmt.Println("hash key:      ", hKey)
	})

	t.Run("failed to generate key", func(t *testing.T) {
		patch := func(b []byte) (n int, err error) {
			return 0, errors.New("monkey error")
		}
		pg := monkey.Patch(rand.Read, patch)
		defer pg.Unpatch()

		mHash, pHash, hKey, err := HashAPI64("kernel32.dll", "WinExec")
		require.ErrorContains(t, err, "monkey error")
		require.Nil(t, mHash)
		require.Nil(t, pHash)
		require.Nil(t, hKey)
	})

	t.Run("invalid key size", func(t *testing.T) {
		patch := func(string, string, []byte) ([]byte, []byte, error) {
			return nil, nil, errors.New("monkey error")
		}
		pg := monkey.Patch(HashAPI64WithKey, patch)
		defer pg.Unpatch()

		mHash, pHash, hKey, err := HashAPI64("kernel32.dll", "WinExec")
		require.ErrorContains(t, err, "monkey error")
		require.Nil(t, mHash)
		require.Nil(t, pHash)
		require.Nil(t, hKey)
	})
}

func TestHashAPI32WithKey(t *testing.T) {
	key := make([]byte, 4)
	binary.LittleEndian.PutUint32(key, 0xCADE960B)

	t.Run("module name-ASCII", func(t *testing.T) {
		mHash, pHash, err := HashAPI32WithKey("kernel32.dll", "WinExec", key)
		require.NoError(t, err)

		expected := uint32(0x42509A1C)
		actual := binary.LittleEndian.Uint32(mHash)
		require.Equal(t, expected, actual)

		expected = uint32(0x3CA3C21A)
		actual = binary.LittleEndian.Uint32(pHash)
		require.Equal(t, expected, actual)
	})

	t.Run("module name-UTF16", func(t *testing.T) {
		mHash, pHash, err := HashAPI32WithKey("测试.dll", "WinExec", key)
		require.NoError(t, err)

		expected := uint32(0x3160B9AD)
		actual := binary.LittleEndian.Uint32(mHash)
		require.Equal(t, expected, actual)

		expected = uint32(0x3CA3C21A)
		actual = binary.LittleEndian.Uint32(pHash)
		require.Equal(t, expected, actual)
	})

	t.Run("invalid key size", func(t *testing.T) {
		mHash, pHash, err := HashAPI32WithKey("kernel32.dll", "WinExec", nil)
		require.EqualError(t, err, "invalid hash api key size")
		require.Nil(t, mHash)
		require.Nil(t, pHash)
	})
}

func TestHashAPI64WithKey(t *testing.T) {
	key := make([]byte, 8)
	binary.LittleEndian.PutUint64(key, 0x7A61A1C72F518C54)

	t.Run("module name-ASCII", func(t *testing.T) {
		mHash, pHash, err := HashAPI64WithKey("kernel32.dll", "WinExec", key)
		require.NoError(t, err)

		expected := uint64(0x2A5175AD1A0CECBC)
		actual := binary.LittleEndian.Uint64(mHash)
		require.Equal(t, expected, actual)

		expected = uint64(0x6596B31A1F68D830)
		actual = binary.LittleEndian.Uint64(pHash)
		require.Equal(t, expected, actual)
	})

	t.Run("module name-UTF16", func(t *testing.T) {
		mHash, pHash, err := HashAPI64WithKey("测试.dll", "WinExec", key)
		require.NoError(t, err)

		expected := uint64(0x635DE9A89022CB4C)
		actual := binary.LittleEndian.Uint64(mHash)
		require.Equal(t, expected, actual)

		expected = uint64(0x6596B31A1F68D830)
		actual = binary.LittleEndian.Uint64(pHash)
		require.Equal(t, expected, actual)
	})

	t.Run("invalid key size", func(t *testing.T) {
		mHash, pHash, err := HashAPI64WithKey("kernel32.dll", "WinExec", nil)
		require.EqualError(t, err, "invalid hash api key size")
		require.Nil(t, mHash)
		require.Nil(t, pHash)
	})
}

func TestBytesToUint64(t *testing.T) {
	t.Run("8 bytes", func(t *testing.T) {
		key := []byte{0x00}
		key = append(key, bytes.Repeat([]byte{0x11}, 6)...)
		key = append(key, 0x33)
		val := BytesToUint64(key)
		require.Equal(t, uint64(0x3311111111111100), val)
	})

	t.Run("4 bytes", func(t *testing.T) {
		key := []byte{0x00}
		key = append(key, bytes.Repeat([]byte{0x11}, 2)...)
		key = append(key, 0x33)
		val := BytesToUint64(key)
		require.Equal(t, uint64(0x33111100), val)
	})

	t.Run("invalid bytes length", func(t *testing.T) {
		val := BytesToUint64(bytes.Repeat([]byte{0x11}, 3))
		require.Zero(t, val)

		val = BytesToUint64(bytes.Repeat([]byte{0x11}, 9))
		require.Zero(t, val)

		val = BytesToUint64(nil)
		require.Zero(t, val)
	})
}
