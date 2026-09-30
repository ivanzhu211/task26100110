package vaultbrowse

import (
	"bytes"
	"image/jpeg"
	"os"
	"path/filepath"
	"testing"
)

// exifAPP1 builds a complete APP1 segment (marker + length + payload).
func exifAPP1(payload []byte) []byte {
	seg := []byte{0xFF, 0xE1, byte(uint16(len(payload)+2) >> 8), byte(len(payload) + 2)}
	return append(seg, payload...)
}

// appSegment builds a complete segment for any marker with a length field.
func appSegment(marker byte, payload []byte) []byte {
	seg := []byte{0xFF, marker, byte(uint16(len(payload)+2) >> 8), byte(len(payload) + 2)}
	return append(seg, payload...)
}

// markerOffsets returns the offsets of the 0xFF byte of every SOS marker and
// of the EOI marker in a well-formed JPEG stream.
func markerOffsets(t *testing.T, data []byte) (sos []int, eoi int) {
	t.Helper()
	inScan := false
	for i := 0; i+1 < len(data); {
		if data[i] != 0xFF {
			i++
			continue
		}
		j := i + 1
		for j < len(data) && data[j] == 0xFF {
			j++
		}
		m := data[j]
		if inScan {
			if m == 0x00 || (m >= 0xD0 && m <= 0xD7) {
				i = j + 1
				continue
			}
			inScan = false
		}
		switch {
		case m == 0x01 || m == 0xD8 || (m >= 0xD0 && m <= 0xD7):
			i = j + 1
		case m == 0xD9:
			return sos, i
		default:
			l := int(data[j+1])<<8 | int(data[j+2])
			if m == 0xDA {
				sos = append(sos, i)
				inScan = true
			}
			i = j + 1 + l
		}
	}
	t.Fatal("no EOI found")
	return nil, -1
}

// insertAll returns data with each blob inserted at the matching offset.
// Offsets must be ascending and refer to positions in data.
func insertAll(data []byte, offsets []int, blobs [][]byte) []byte {
	var out []byte
	prev := 0
	for k, off := range offsets {
		out = append(out, data[prev:off]...)
		out = append(out, blobs[k]...)
		prev = off
	}
	return append(out, data[prev:]...)
}

func decodePixels(t *testing.T, data []byte) []byte {
	t.Helper()
	img, err := jpeg.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("jpeg.Decode: %v", err)
	}
	b := img.Bounds()
	var buf bytes.Buffer
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, a := img.At(x, y).RGBA()
			buf.Write([]byte{byte(r >> 8), byte(g >> 8), byte(bl >> 8), byte(a >> 8)})
		}
	}
	return buf.Bytes()
}

func scrubToFile(t *testing.T, src []byte) []byte {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "out.jpg")
	if err := ScrubJPEG(bytes.NewReader(src), dst); err != nil {
		t.Fatalf("ScrubJPEG: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return got
}

// TestScrubRealJPEG inserts EXIF APP1 segments before the first scan,
// between scans, and after the final scan of decodable baseline and
// multi-scan progressive JPEGs, then verifies exact byte restoration,
// pixel-identical decoding, and idempotency.
func TestScrubRealJPEG(t *testing.T) {
	for _, name := range []string{"baseline.jpg", "progressive.jpg"} {
		t.Run(name, func(t *testing.T) {
			orig, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			sos, eoi := markerOffsets(t, orig)
			if name == "progressive.jpg" && len(sos) < 2 {
				t.Fatalf("progressive fixture has only %d scans", len(sos))
			}

			// EXIF payloads: one with plausible TIFF header, one with
			// corrupted TIFF garbage that must still be dropped.
			exifA := exifAPP1([]byte("Exif\x00\x00II*\x00\x08\x00\x00\x00broken-tiff"))
			// exifB also exercises a segment length above 255 bytes.
			exifB := exifAPP1([]byte("Exif\x00\x00\xff\xd9\xff\x00corrupt\xff\xe1garbage" +
				string(bytes.Repeat([]byte{0xAB}, 300))))

			var offsets []int
			var blobs [][]byte
			for k, off := range sos {
				offsets = append(offsets, off)
				if k%2 == 0 {
					blobs = append(blobs, exifA)
				} else {
					blobs = append(blobs, exifB)
				}
			}
			offsets = append(offsets, eoi)
			blobs = append(blobs, exifA)

			withExif := insertAll(orig, offsets, blobs)

			got := scrubToFile(t, withExif)
			if !bytes.Equal(got, orig) {
				t.Fatalf("scrubbed output differs from original bytes")
			}

			if a, b := decodePixels(t, got), decodePixels(t, orig); !bytes.Equal(a, b) {
				t.Fatalf("decoded pixels changed")
			}

			again := scrubToFile(t, got)
			if !bytes.Equal(again, got) {
				t.Fatalf("scrubbing is not idempotent")
			}
		})
	}
}

// TestStructuralFixture feeds a hand-crafted stream mixing non-EXIF APP1
// segments, EXIF signatures embedded inside other segments, FF00 stuffing,
// restart markers, and FF fill runs, and verifies that only the real EXIF
// APP1 segments are removed while every other byte is preserved.
func TestStructuralFixture(t *testing.T) {
	var fixture, want []byte
	emit := func(b ...byte) {
		fixture = append(fixture, b...)
		want = append(want, b...)
	}
	emitSeg := func(seg []byte) {
		fixture = append(fixture, seg...)
		want = append(want, seg...)
	}
	dropSeg := func(seg []byte) {
		fixture = append(fixture, seg...)
	}

	// SOI, then FF fill bytes before the next marker (kept verbatim).
	emit(0xFF, 0xD8, 0xFF, 0xFF)

	// Non-EXIF APP1 (XMP) must survive.
	emitSeg(appSegment(0xE1, []byte("http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta/>")))
	// Real EXIF #1: dropped.
	dropSeg(exifAPP1([]byte("Exif\x00\x00MM\x00*\x00\x00\x00\x08")))
	// APP1 whose payload starts with "Exif" but not two zero bytes: kept.
	emitSeg(appSegment(0xE1, []byte("Exif\x00\x01not-really-exif")))
	// APP2 (ICC) containing an EXIF signature inside the payload: kept.
	emitSeg(appSegment(0xE2, []byte("ICC_PROFILE\x00\x01Exif\x00\x00inside")))
	// COM containing an EXIF signature: kept.
	emitSeg(appSegment(0xFE, []byte("comment with Exif\x00\x00 inside")))
	// Minimal DQT/SOF0/DHT stand-ins (payload content is opaque here).
	emitSeg(appSegment(0xDB, []byte{0x00, 1, 2, 3, 4}))
	emitSeg(appSegment(0xC0, []byte{0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00}))
	emitSeg(appSegment(0xC4, []byte{0x00, 0x01, 0x00, 0x00}))

	// SOS header, then scan data.
	emitSeg(appSegment(0xDA, []byte{0x01, 0x01, 0x00, 0x00, 0x3F, 0x00}))
	// Plain entropy bytes, including a bare 0xE1 data byte.
	emit(0x11, 0x22, 0xE1, 0x33)
	// FF00 stuffing followed by bytes that look like an APP1 EXIF
	// segment; inside scan data this is literal data and must be kept.
	emit(0xFF, 0x00, 0xE1, 0x00, 0x0A, 'E', 'x', 'i', 'f', 0x00, 0x00, 0x99)
	// FF fill run then stuffed byte, then RST3, then more data.
	emit(0xFF, 0xFF, 0x00, 0x44, 0xFF, 0xD3, 0x55)
	// FF fill run then restart marker RST0.
	emit(0xFF, 0xFF, 0xD0, 0x66)

	// FF fill bytes, then real EXIF #2 right after the scan: dropped,
	// fill bytes kept.
	emit(0xFF, 0xFF)
	dropSeg(exifAPP1([]byte("Exif\x00\x00corrupted-tiff\xff\xd9\xff")))

	// Non-EXIF APP1 after the last scan: kept.
	emitSeg(appSegment(0xE1, []byte("http://ns.adobe.com/xmp/extension/\x00")))
	// Real EXIF #3 after the last scan: dropped.
	dropSeg(exifAPP1([]byte("Exif\x00\x00II*\x00")))

	// EOI and trailing garbage after EOI: kept verbatim.
	emit(0xFF, 0xD9, 0x00, 0xFF, 0xE1, 't', 'r', 'a', 'i', 'l')

	got := scrubToFile(t, fixture)
	if !bytes.Equal(got, want) {
		t.Fatalf("structural fixture mismatch:\n got %x\nwant %x", got, want)
	}

	again := scrubToFile(t, got)
	if !bytes.Equal(again, want) {
		t.Fatalf("scrubbing is not idempotent")
	}
}

// TestTruncatedInput verifies malformed streams are reported as errors.
func TestTruncatedInput(t *testing.T) {
	truncated := []byte{0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x20, 'E', 'x'}
	dst := filepath.Join(t.TempDir(), "out.jpg")
	if err := ScrubJPEG(bytes.NewReader(truncated), dst); err == nil {
		t.Fatal("expected error for truncated segment")
	}
}
