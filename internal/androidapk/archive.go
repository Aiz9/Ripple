package androidapk

import (
	"fmt"
	"io"
)

// Inspect the bounded central-directory structure before archive/zip allocates
// per-entry metadata. Uploaded APKs must not control an unbounded allocation
// through a forged EOCD entry count or millions of tiny directory records.
// ZIP64/multidisk/polyglot offset layouts are deliberately unsupported here.
func preflightAPK(r io.ReaderAt, size int64) error {
	if size < 22 || size > 256<<20 {
		return fmt.Errorf("APK must be a ZIP archive up to 256 MiB")
	}
	tailSize := int64(22 + 65535)
	if size < tailSize {
		tailSize = size
	}
	tail := make([]byte, int(tailSize))
	if _, err := r.ReadAt(tail, size-tailSize); err != nil {
		return err
	}
	end := -1
	for i := len(tail) - 22; i >= 0; i-- {
		if u32(tail, i) == 0x06054b50 && i+22+int(u16(tail, i+20)) == len(tail) {
			end = i
			break
		}
	}
	if end < 0 {
		return fmt.Errorf("APK ZIP end record is missing or has trailing data")
	}
	if u16(tail, end+4) != 0 || u16(tail, end+6) != 0 || u16(tail, end+8) != u16(tail, end+10) {
		return fmt.Errorf("multidisk APK archives are not supported")
	}
	count := int(u16(tail, end+10))
	directorySize, offset := int64(u32(tail, end+12)), int64(u32(tail, end+16))
	absoluteEnd := size - tailSize + int64(end)
	if count == 65535 || directorySize == 0xffffffff || offset == 0xffffffff {
		return fmt.Errorf("ZIP64 is not supported by the bounded APK inspector")
	}
	if directorySize > 16<<20 || offset+directorySize != absoluteEnd || offset < 0 {
		return fmt.Errorf("APK central directory exceeds its limit or has unsupported offsets")
	}
	directory := make([]byte, int(directorySize))
	if _, err := r.ReadAt(directory, offset); err != nil {
		return err
	}
	actual := 0
	for pos := 0; pos < len(directory); {
		if len(directory)-pos < 46 || u32(directory, pos) != 0x02014b50 {
			return fmt.Errorf("invalid APK central directory record")
		}
		length := 46 + int(u16(directory, pos+28)) + int(u16(directory, pos+30)) + int(u16(directory, pos+32))
		if length > len(directory)-pos {
			return fmt.Errorf("truncated APK directory record")
		}
		actual++
		if actual > 100000 || actual > count {
			return fmt.Errorf("APK directory entry count exceeds the declared limit")
		}
		pos += length
	}
	if actual != count {
		return fmt.Errorf("APK directory entry count mismatch")
	}
	return nil
}
