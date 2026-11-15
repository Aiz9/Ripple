// Package androidapk performs bounded, offline inspection of Android APKs.
package androidapk

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"unicode/utf16"
)

const androidNS = "http://schemas.android.com/apk/res/android"

type element struct {
	name     string
	attrs    map[string]string
	children []*element
}

func (e *element) attr(name string) string { return e.attrs[androidNS+":"+name] }

func parseManifest(data []byte) (*element, error) { return parseXMLRoot(data, "manifest") }

func parseXMLRoot(data []byte, expected string) (*element, error) {
	if len(data) > 4<<20 {
		return nil, fmt.Errorf("manifest exceeds 4 MiB")
	}
	if len(data) >= 8 && binary.LittleEndian.Uint16(data) == 3 {
		return parseBinaryXMLRoot(data, expected)
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	var root *element
	var stack []*element
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid manifest XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			e := &element{name: t.Name.Local, attrs: map[string]string{}}
			for _, a := range t.Attr {
				key := a.Name.Local
				if a.Name.Space != "" {
					key = a.Name.Space + ":" + key
				}
				e.attrs[key] = a.Value
			}
			if len(stack) == 0 {
				if root != nil {
					return nil, fmt.Errorf("multiple manifest roots")
				}
				root = e
			} else {
				p := stack[len(stack)-1]
				p.children = append(p.children, e)
			}
			stack = append(stack, e)
			if len(stack) > 256 {
				return nil, fmt.Errorf("manifest nesting exceeds limit")
			}
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		}
	}
	if root == nil || root.name != expected {
		return nil, fmt.Errorf("APK has no manifest root")
	}
	return root, nil
}

func u16(b []byte, i int) uint16 { return binary.LittleEndian.Uint16(b[i : i+2]) }
func u32(b []byte, i int) uint32 { return binary.LittleEndian.Uint32(b[i : i+4]) }

// Android's resource XML stores a string pool followed by namespace and element
// chunks. Decode attributes directly, without shelling out to an SDK utility.
func parseBinaryManifest(data []byte) (*element, error) { return parseBinaryXMLRoot(data, "manifest") }
func parseBinaryXMLRoot(data []byte, expected string) (*element, error) {
	end := int(u32(data, 4))
	header := int(u16(data, 2))
	if end != len(data) || header < 8 || header > end {
		return nil, fmt.Errorf("invalid binary XML header")
	}
	var pool []string
	var root *element
	var stack []*element
	str := func(index uint32) (string, error) {
		if index == 0xffffffff {
			return "", nil
		}
		if uint64(index) >= uint64(len(pool)) {
			return "", fmt.Errorf("invalid string index")
		}
		return pool[index], nil
	}
	for off := header; off < end; {
		if end-off < 8 {
			return nil, fmt.Errorf("truncated XML chunk")
		}
		typ, hs, size := u16(data, off), int(u16(data, off+2)), int(u32(data, off+4))
		if hs < 8 || size < hs || size > end-off {
			return nil, fmt.Errorf("invalid XML chunk size")
		}
		c := data[off : off+size]
		switch typ {
		case 1:
			var err error
			pool, err = decodeStringPool(c)
			if err != nil {
				return nil, err
			}
		case 0x102:
			if hs < 16 || size-hs < 20 {
				return nil, fmt.Errorf("truncated element")
			}
			name, err := str(u32(c, hs+4))
			if err != nil {
				return nil, err
			}
			e := &element{name: name, attrs: map[string]string{}}
			start, step, count := hs+int(u16(c, hs+8)), int(u16(c, hs+10)), int(u16(c, hs+12))
			if step < 20 || start < hs+20 || start > size || count > (size-start)/step {
				return nil, fmt.Errorf("invalid attribute table")
			}
			for i := 0; i < count; i++ {
				a := c[start+i*step : start+i*step+20]
				ns, err := str(u32(a, 0))
				if err != nil {
					return nil, err
				}
				key, err := str(u32(a, 4))
				if err != nil {
					return nil, err
				}
				var value string
				if u32(a, 8) != 0xffffffff {
					value, err = str(u32(a, 8))
				} else {
					v := u32(a, 16)
					switch a[15] {
					case 3:
						value, err = str(v)
					case 0x12:
						value = strconv.FormatBool(v != 0)
					case 0x10:
						value = strconv.FormatUint(uint64(v), 10)
					default:
						value = fmt.Sprintf("@0x%08x", v)
					}
				}
				if err != nil {
					return nil, err
				}
				if ns != "" {
					key = ns + ":" + key
				}
				e.attrs[key] = value
			}
			if len(stack) == 0 {
				if root != nil {
					return nil, fmt.Errorf("multiple manifest roots")
				}
				root = e
			} else {
				p := stack[len(stack)-1]
				p.children = append(p.children, e)
			}
			stack = append(stack, e)
			if len(stack) > 256 {
				return nil, fmt.Errorf("manifest nesting exceeds limit")
			}
		case 0x103:
			if len(stack) == 0 || hs < 16 || size-hs < 8 {
				return nil, fmt.Errorf("unbalanced manifest element")
			}
			name, err := str(u32(c, hs+4))
			if err != nil || name != stack[len(stack)-1].name {
				return nil, fmt.Errorf("mismatched manifest element")
			}
			stack = stack[:len(stack)-1]
		}
		off += size
	}
	if root == nil || root.name != expected || len(stack) != 0 {
		return nil, fmt.Errorf("incomplete binary manifest")
	}
	return root, nil
}

func decodeStringPool(c []byte) ([]string, error) {
	if len(c) < 28 {
		return nil, fmt.Errorf("truncated string pool")
	}
	hs, count, styles, start := int(u16(c, 2)), int(u32(c, 8)), int(u32(c, 12)), int(u32(c, 20))
	if hs < 28 || hs > len(c) || count > 200000 || count > (len(c)-hs)/4 || styles > (len(c)-hs-count*4)/4 || start < hs+(count+styles)*4 || start > len(c) {
		return nil, fmt.Errorf("invalid string pool")
	}
	utf8 := u32(c, 16)&0x100 != 0
	result := make([]string, count)
	decodedBytes := 0
	for i := range result {
		pos := start + int(u32(c, hs+i*4))
		if pos < start || pos >= len(c) {
			return nil, fmt.Errorf("invalid string offset")
		}
		length := func(wide bool) (int, error) {
			if wide {
				if len(c)-pos < 2 {
					return 0, io.ErrUnexpectedEOF
				}
				n := int(u16(c, pos))
				pos += 2
				if n&0x8000 != 0 {
					if len(c)-pos < 2 {
						return 0, io.ErrUnexpectedEOF
					}
					n = (n&0x7fff)<<16 | int(u16(c, pos))
					pos += 2
				}
				return n, nil
			}
			if pos >= len(c) {
				return 0, io.ErrUnexpectedEOF
			}
			n := int(c[pos])
			pos++
			if n&0x80 != 0 {
				if pos >= len(c) {
					return 0, io.ErrUnexpectedEOF
				}
				n = (n&0x7f)<<8 | int(c[pos])
				pos++
			}
			return n, nil
		}
		if utf8 {
			if _, err := length(false); err != nil {
				return nil, err
			}
			n, err := length(false)
			if err != nil || n >= len(c)-pos {
				return nil, fmt.Errorf("truncated UTF-8 string")
			}
			if c[pos+n] != 0 {
				return nil, fmt.Errorf("invalid UTF-8 terminator")
			}
			decodedBytes += n
			if decodedBytes > 16<<20 {
				return nil, fmt.Errorf("decoded string pool exceeds limit")
			}
			result[i] = string(c[pos : pos+n])
		} else {
			n, err := length(true)
			if err != nil || len(c)-pos < 2 || n > (len(c)-pos-2)/2 {
				return nil, fmt.Errorf("truncated UTF-16 string")
			}
			decodedBytes += n * 2
			if decodedBytes > 16<<20 {
				return nil, fmt.Errorf("decoded string pool exceeds limit")
			}
			units := make([]uint16, n)
			for j := range units {
				units[j] = u16(c, pos+j*2)
			}
			if u16(c, pos+n*2) != 0 {
				return nil, fmt.Errorf("invalid UTF-16 terminator")
			}
			result[i] = string(utf16.Decode(units))
		}
	}
	return result, nil
}
