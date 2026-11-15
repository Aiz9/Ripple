package androidapk

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// dexAppURLs attributes const-string operands to classes in the manifest package.
// Invalid/unsupported instructions stop that method; operands are never scanned
// as opcodes. Obfuscated packages and constructed URLs require runtime evidence.
func dexAppURLs(data []byte, pkg string) map[string]string {
	out := map[string]string{}
	work, decoded := 2000000, 0
	if len(data) < 112 || !bytes.HasPrefix(data, []byte("dex\n")) || string(data[4:7]) > "040" || u32(data, 40) != 0x12345678 {
		return out
	}
	table := func(sizeAt, offAt, width int) (int, int, bool) {
		n, off := int(u32(data, sizeAt)), int(u32(data, offAt))
		return n, off, n >= 0 && n <= 400000 && off >= 0 && off <= len(data) && n <= (len(data)-off)/width
	}
	sn, so, ok := table(56, 60, 4)
	if !ok {
		return out
	}
	tn, to, ok := table(64, 68, 4)
	if !ok {
		return out
	}
	cn, co, ok := table(96, 100, 32)
	if !ok {
		return out
	}
	uleb := func(at *int) (uint32, bool) {
		var value uint32
		for i := 0; i < 5; i++ {
			if *at < 0 || *at >= len(data) {
				return 0, false
			}
			b := data[*at]
			*at++
			if i == 4 && b > 15 {
				return 0, false
			}
			value |= uint32(b&127) << uint(7*i)
			if b < 128 {
				return value, true
			}
		}
		return 0, false
	}
	str := func(index uint32) string {
		if decoded > 16<<20 {
			return ""
		}
		if uint64(index) >= uint64(sn) {
			return ""
		}
		at := int(u32(data, so+int(index)*4))
		if _, ok := uleb(&at); !ok {
			return ""
		}
		end := at
		for end < len(data) && end-at < 16384 && data[end] != 0 {
			end++
		}
		if end >= len(data) || end-at >= 16384 {
			return ""
		}
		decoded += end - at
		return string(data[at:end])
	}
	prefix := "L" + strings.ReplaceAll(pkg, ".", "/") + "/"
	for c := 0; c < cn; c++ {
		work--
		if work <= 0 || decoded > 16<<20 {
			return out
		}
		base := co + c*32
		typeID := u32(data, base)
		if uint64(typeID) >= uint64(tn) {
			continue
		}
		owner := str(u32(data, to+int(typeID)*4))
		if !strings.HasPrefix(owner, prefix) {
			continue
		}
		at := int(u32(data, base+24))
		if at == 0 {
			continue
		}
		counts := [4]uint32{}
		valid := true
		for i := range counts {
			v, ok := uleb(&at)
			if !ok || v > 200000 {
				valid = false
				break
			}
			counts[i] = v
		}
		if !valid {
			continue
		}
		for i := uint32(0); i < counts[0]+counts[1]; i++ {
			work--
			if work <= 0 {
				return out
			}
			if _, ok := uleb(&at); !ok {
				valid = false
				break
			}
			if _, ok := uleb(&at); !ok {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		for m := uint32(0); m < counts[2]+counts[3]; m++ {
			work--
			if work <= 0 {
				return out
			}
			if _, ok := uleb(&at); !ok {
				break
			}
			if _, ok := uleb(&at); !ok {
				break
			}
			code, ok := uleb(&at)
			if !ok {
				break
			}
			off := int(code)
			if off <= 0 || off > len(data)-16 {
				continue
			}
			n := int(u32(data, off+12))
			if n < 0 || n > 1000000 || n > (len(data)-off-16)/2 {
				continue
			}
			ins := data[off+16 : off+16+n*2]
			for pc := 0; pc < n; {
				work--
				if work <= 0 || len(out) >= 2000 {
					return out
				}
				unit := binary.LittleEndian.Uint16(ins[pc*2:])
				op := byte(unit)
				width := dexInstructionWidth(op)
				if op == 0 && unit != 0 {
					if pc+2 > n {
						break
					}
					size := int(binary.LittleEndian.Uint16(ins[(pc+1)*2:]))
					switch unit {
					case 0x0100:
						width = 4 + size*2
					case 0x0200:
						width = 2 + size*4
					case 0x0300:
						if pc+4 > n {
							width = 0
							break
						}
						items := uint64(binary.LittleEndian.Uint32(ins[(pc+2)*2:]))
						bytes := uint64(size) * items
						if bytes > uint64(len(ins)) {
							width = 0
						} else {
							width = 4 + int((bytes+1)/2)
						}
					default:
						width = 0
					}
				}
				if width == 0 || width > n-pc {
					break
				}
				if op == 0x1a || op == 0x1b {
					index := uint32(binary.LittleEndian.Uint16(ins[(pc+1)*2:]))
					if op == 0x1b {
						index = binary.LittleEndian.Uint32(ins[(pc+1)*2:])
					}
					value := str(index)
					for _, candidate := range literalURL.FindAllString(value, 32) {
						out[strings.TrimRight(candidate, ".,;)}]")] = strings.TrimSuffix(strings.TrimPrefix(owner, "L"), ";")
					}
				}
				pc += width
			}
		}
	}
	return out
}

func dexInstructionWidth(op byte) int {
	switch {
	case op == 0x02 || op == 0x05 || op == 0x08 || op == 0x13 || op == 0x15 || op == 0x16 || op == 0x19 || op == 0x1a || op == 0x1c || op == 0x1f || op == 0x20 || op == 0x22 || op == 0x23 || op == 0x29:
		return 2
	case op == 0x03 || op == 0x06 || op == 0x09 || op == 0x14 || op == 0x17 || op == 0x1b || op == 0x24 || op == 0x25 || op == 0x26 || op == 0x2a || op == 0x2b || op == 0x2c:
		return 3
	case op == 0x18:
		return 5
	case op >= 0x2d && op <= 0x3d, op >= 0x44 && op <= 0x6d, op >= 0x90 && op <= 0xaf, op >= 0xd0 && op <= 0xe2, op >= 0xfe:
		return 2
	case op >= 0x6e && op <= 0x72, op >= 0x74 && op <= 0x78, op == 0xfc || op == 0xfd:
		return 3
	case op == 0xfa || op == 0xfb:
		return 4
	case op >= 0x3e && op <= 0x43, op == 0x73, op == 0x79 || op == 0x7a, op >= 0xe3 && op <= 0xf9:
		return 0
	default:
		return 1
	}
}

func resourceTableStrings(data []byte) []string {
	if len(data) < 12 || u16(data, 0) != 2 {
		return nil
	}
	header, end := int(u16(data, 2)), int(u32(data, 4))
	if header < 12 || end > len(data) {
		return nil
	}
	for at := header; at <= end-8; {
		size := int(u32(data, at+4))
		if size < 8 || size > end-at {
			return nil
		}
		if u16(data, at) == 1 {
			pool, err := decodeStringPool(data[at : at+size])
			if err == nil {
				return pool
			}
			return nil
		}
		at += size
	}
	return nil
}
