// Package middleware provides HTTP authentication middleware for Go servers.
//
// Base2048 encoding uses two Unicode character tables:
//   - pairsTable  (2048 runes): each rune represents 11 bits of data.
//   - paddingTable (256 runes): encodes the final 1–8 leftover bits when the
//     total bit count is not a multiple of 11.
//
// The tables used here cover CJK Unified Ideographs (U+4E00–U+55FF) for the
// 2048-symbol alphabet and Hangul Syllables (U+AC00–U+ACFF) for the 256-symbol
// padding alphabet.  Both ranges consist entirely of defined Unicode code points.
// Any Base2048 client must use the same tables for interoperability.
package middleware

import (
	"errors"
	"strings"
	"unicode/utf8"
)

const (
	bitsPerPair    = 11 // bits encoded by one pair character
	bitsPerPadding = 8  // bits encoded by one padding character

	pairsBase   = 0x4E00 // first CJK Unified Ideograph
	paddingBase = 0xAC00 // first Hangul Syllable
)

// isPairRune reports whether r is in the 2048-rune table.
func isPairRune(r rune) bool {
	return r >= pairsBase && r < pairsBase+2048
}

// isPaddingRune reports whether r is in the 256-rune table.
func isPaddingRune(r rune) bool {
	return r >= paddingBase && r < paddingBase+256
}

// Base2048Encode encodes src into a Base2048 string.
func Base2048Encode(src []byte) string {
	if len(src) == 0 {
		return ""
	}

	totalBits := len(src) * 8
	// number of full 11-bit pairs
	fullPairs := totalBits / bitsPerPair
	// remaining bits after full pairs
	remBits := totalBits % bitsPerPair

	var sb strings.Builder
	// upper bound: fullPairs + (1 if remBits>0)
	sb.Grow((fullPairs + 1) * utf8.UTFMax)

	bitBuf := uint64(0)
	bitsInBuf := 0
	byteIdx := 0

	for i := 0; i < fullPairs; i++ {
		// fill up buffer until we have at least 11 bits
		for bitsInBuf < bitsPerPair {
			bitBuf = (bitBuf << 8) | uint64(src[byteIdx])
			byteIdx++
			bitsInBuf += 8
		}
		bitsInBuf -= bitsPerPair
		idx := (bitBuf >> uint(bitsInBuf)) & 0x7FF
		sb.WriteRune(rune(pairsBase + idx))
	}

	// encode leftover bits with padding character
	if remBits > 0 {
		// collect remaining bits
		for byteIdx < len(src) {
			bitBuf = (bitBuf << 8) | uint64(src[byteIdx])
			byteIdx++
			bitsInBuf += 8
		}
		// shift left to top of 8-bit slot
		leftover := (bitBuf << uint(8-bitsInBuf)) & 0xFF
		sb.WriteRune(rune(paddingBase + leftover))
	}

	return sb.String()
}

// Base2048Decode decodes a Base2048 string into bytes, reusing buf when it is
// large enough to hold the result (to work well with sync.Pool).  The returned
// slice is a sub-slice of buf if buf is large enough; otherwise a new slice is
// allocated.
func Base2048Decode(s string, buf []byte) ([]byte, error) {
	if s == "" {
		return buf[:0], nil
	}

	runes := []rune(s)
	n := len(runes)
	if n == 0 {
		return buf[:0], nil
	}

	// Last rune determines whether there's a padding character.
	lastR := runes[n-1]
	hasPadding := isPaddingRune(lastR)
	pairCount := n
	if hasPadding {
		pairCount = n - 1
	}

	// Validate all pair runes.
	for i := 0; i < pairCount; i++ {
		if !isPairRune(runes[i]) {
			return nil, errors.New("base2048: invalid character at position " + itoa(i))
		}
	}

	totalBits := pairCount*bitsPerPair
	if hasPadding {
		totalBits += bitsPerPadding
	}
	totalBytes := totalBits / 8

	// Allocate or reuse buffer.
	if cap(buf) < totalBytes {
		buf = make([]byte, totalBytes)
	}
	out := buf[:totalBytes]

	bitBuf := uint64(0)
	bitsInBuf := 0
	outIdx := 0

	for i := 0; i < pairCount; i++ {
		val := uint64(runes[i] - pairsBase)
		bitBuf = (bitBuf << bitsPerPair) | val
		bitsInBuf += bitsPerPair
		for bitsInBuf >= 8 {
			bitsInBuf -= 8
			out[outIdx] = byte(bitBuf >> uint(bitsInBuf))
			outIdx++
		}
	}

	if hasPadding {
		val := uint64(lastR - paddingBase)
		// The padding character encodes the top bitsInBuf+8 bits but only the
		// leading (8-bitsInBuf) meaningful ones are new data.
		newBits := 8 - bitsInBuf
		bitBuf = (bitBuf << uint(newBits)) | (val >> uint(bitsInBuf))
		bitsInBuf += newBits
		if bitsInBuf >= 8 {
			bitsInBuf -= 8
			out[outIdx] = byte(bitBuf >> uint(bitsInBuf))
			outIdx++
		}
	}

	return out[:outIdx], nil
}

// itoa is a minimal int-to-string helper to avoid importing strconv here.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
