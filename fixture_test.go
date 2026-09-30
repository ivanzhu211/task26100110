package vaultbrowse

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

// exifPayload is a minimal EXIF APP1 payload: signature plus a deliberately
// corrupt TIFF body, to prove the scrubber never parses TIFF.
var exifPayload = append([]byte("Exif\x00\x00"), 0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xD8, 0xFF)

// makeSegment builds a complete segment: 0xFF, marker, length, payload.
func makeSegment(marker byte, payload []byte) []byte {
	seg := make([]byte, 4+len(payload))
	seg[0] = 0xFF
	seg[1] = marker
	binary.BigEndian.PutUint16(seg[2:], uint16(2+len(payload)))
	copy(seg[4:], payload)
	return seg
}

// insertAt returns data with seg inserted at offset off.
func insertAt(data []byte, off int, seg []byte) []byte {
	out := make([]byte, 0, len(data)+len(seg))
	out = append(out, data[:off]...)
	out = append(out, seg...)
	out = append(out, data[off:]...)
	return out
}

// markerIndex records where structural markers live in a JPEG stream.
type markerIndex struct {
	sosOffsets []int // offset of the 0xFF of each SOS marker
	eoiOffset  int   // offset of the 0xFF of the EOI marker
}

// indexJPEG walks a JPEG stream and locates SOS and EOI markers, correctly
// skipping entropy-coded scan data. It mirrors the JPEG structure rules and
// is used by tests to choose EXIF insertion points.
func indexJPEG(t *testing.T, data []byte) markerIndex {
	t.Helper()
	if len(data) < 2 || data[0] != 0xFF || data[1] != 0xD8 {
		t.Fatal("fixture missing SOI")
	}
	var idx markerIndex
	pos := 2
	for pos < len(data) {
		if data[pos] != 0xFF {
			t.Fatalf("expected 0xFF at offset %d, got 0x%02X", pos, data[pos])
		}
		for pos < len(data) && data[pos] == 0xFF {
			pos++
		}
		marker := data[pos]
		pos++
		switch {
		case marker == 0x00 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD8):
			// no length field
		case marker == 0xD9:
			idx.eoiOffset = pos - 2
			return idx
		case marker == 0xDA:
			idx.sosOffsets = append(idx.sosOffsets, pos-2)
			segLen := int(binary.BigEndian.Uint16(data[pos:]))
			pos += segLen
			// skip scan data
			for pos < len(data) {
				if data[pos] != 0xFF {
					pos++
					continue
				}
				runEnd := pos
				for runEnd < len(data) && data[runEnd] == 0xFF {
					runEnd++
				}
				if runEnd >= len(data) {
					pos = runEnd
					break
				}
				next := data[runEnd]
				if next == 0x00 || (next >= 0xD0 && next <= 0xD7) {
					pos = runEnd + 1
					continue
				}
				break
			}
		default:
			segLen := int(binary.BigEndian.Uint16(data[pos:]))
			pos += segLen
		}
	}
	t.Fatal("fixture missing EOI")
	return idx
}

// scrubToString runs ScrubJPEG on input and returns the result bytes.
func scrubToString(t *testing.T, input []byte) []byte {
	t.Helper()
	dst := t.TempDir() + "/out.jpg"
	if err := ScrubJPEG(bytes.NewReader(input), dst); err != nil {
		t.Fatalf("ScrubJPEG: %v", err)
	}
	out, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read scrubbed output: %v", err)
	}
	return out
}
