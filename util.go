package smb2

import (
	"os"
	"syscall"
	"time"
	"unicode/utf16"
)

func timeToFiletime(tm time.Time) int64 {
	nsec := tm.UnixNano()
	// convert into 100-nanosecond
	nsec /= 100
	// change starting time to January 1, 1601
	nsec += 116444736000000000
	return nsec
}

// NOTE: not efficient, but enough for now
func stringToUtf16le(str string) []byte {
	r0 := utf16.Encode([]rune(str))
	r := make([]byte, len(r0)*2)
	for i := 0; i < len(r0); i++ {
		r[i*2] = byte(r0[i] & 0xFF)
		r[i*2+1] = byte(r0[i] >> 8)
	}
	return r
}

// NOTE: not efficient, but enough for now
func utf16leToString(str []byte) string {

	t := make([]uint16, len(str)/2)
	for i := 0; i < len(t); i++ {
		t[i] = uint16(str[i*2]) + uint16(str[i*2+1]<<8)
	}
	return string(utf16.Decode(t))
}

func statAccessTime(fi os.FileInfo) time.Time {
	if ss, ok := fi.Sys().(*syscall.Stat_t); ok {
		return time.Unix(int64(ss.Atim.Sec), int64(ss.Atim.Nsec))
	}
	return fi.ModTime()
}

func calcPadding(offset int, align int) int {
	return (-offset) & (align - 1)
}

func calcAlignedOffset(offset int, align int) int {
	return (offset + align - 1) &^ (align - 1)
}
