package vaultbrowse

import (
	"bytes"
	"image"
	"image/jpeg"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func decodePixels(t *testing.T, data []byte) image.Image {
	t.Helper()
	img, err := jpeg.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("jpeg.Decode: %v", err)
	}
	return img
}

func assertSamePixels(t *testing.T, a, b image.Image) {
	t.Helper()
	if !a.Bounds().Eq(b.Bounds()) {
		t.Fatalf("bounds differ: %v vs %v", a.Bounds(), b.Bounds())
	}
	bounds := a.Bounds()
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			ar, ag, ab, aa := a.At(x, y).RGBA()
			br, bg, bb, ba := b.At(x, y).RGBA()
			if ar != br || ag != bg || ab != bb || aa != ba {
				t.Fatalf("pixel (%d,%d) differs: (%d,%d,%d,%d) vs (%d,%d,%d,%d)",
					x, y, ar, ag, ab, aa, br, bg, bb, ba)
			}
		}
	}
}

// TestScrubRealJPEG inserts EXIF segments before the first scan, between
// scans and after the last scan of decodable baseline and progressive JPEGs,
// then checks exact output bytes, pixel equality and idempotency.
func TestScrubRealJPEG(t *testing.T) {
	for _, name := range []string{"baseline.jpg", "progressive.jpg"} {
		t.Run(name, func(t *testing.T) {
			original := loadFixture(t, name)
			idx := indexJPEG(t, original)

			exifSeg := makeSegment(0xE1, exifPayload)

			// Insertion points: after SOI (before first scan), between
			// scans (before the middle SOS) and after the last scan
			// (before EOI).
			type insertion struct {
				off int
				seg []byte
			}
			insertions := []insertion{
				{2, exifSeg},
				{idx.eoiOffset, exifSeg},
			}
			if len(idx.sosOffsets) > 1 {
				mid := idx.sosOffsets[len(idx.sosOffsets)/2]
				insertions = append(insertions, insertion{mid, exifSeg})
			}
			// Apply from the highest offset down so offsets stay valid.
			sort.Slice(insertions, func(i, j int) bool { return insertions[i].off > insertions[j].off })
			exified := original
			for _, ins := range insertions {
				exified = insertAt(exified, ins.off, ins.seg)
			}

			scrubbed := scrubToString(t, exified)
			if !bytes.Equal(scrubbed, original) {
				t.Fatalf("scrubbed output differs from original:\n got %d bytes\nwant %d bytes",
					len(scrubbed), len(original))
			}

			assertSamePixels(t, decodePixels(t, original), decodePixels(t, scrubbed))

			// Scrubbing again must be a no-op.
			again := scrubToString(t, scrubbed)
			if !bytes.Equal(again, scrubbed) {
				t.Fatal("second scrub changed the output")
			}
		})
	}
}

// TestStructuralFixture feeds a hand-built stream mixing non-EXIF APP1
// segments, fake EXIF signatures inside other segments and scan data, FF00
// stuffing, restart markers and FF padding, and verifies that only the real
// EXIF APP1 segments are removed.
func TestStructuralFixture(t *testing.T) {
	soi := []byte{0xFF, 0xD8}

	// APP0 whose payload contains a fake EXIF signature: must survive.
	app0 := makeSegment(0xE0, append([]byte("JFIF\x00fake:"), exifPayload...))
	// Non-EXIF APP1 (XMP): must survive.
	xmpPayload := append([]byte("http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta/>"), 0x01)
	app1XMP := makeSegment(0xE1, xmpPayload)
	// Real EXIF segment #1: removed.
	app1Exif1 := makeSegment(0xE1, exifPayload)
	// COM containing the EXIF signature: must survive.
	com := makeSegment(0xFE, append([]byte("note:"), exifPayload...))
	// APP2 ICC profile: must survive.
	app2 := makeSegment(0xE2, []byte("ICC_PROFILE\x00\x01\x01payload"))
	// Real EXIF segment #2, preceded by two extra FF padding bytes.
	exif2Padding := []byte{0xFF, 0xFF}
	app1Exif2 := makeSegment(0xE1, append([]byte("Exif\x00\x00"), 0x00, 0x11, 0x22))

	sosHeader := makeSegment(0xDA, []byte{0x01, 0x01, 0x00, 0x00, 0x3F, 0x00})
	// Scan data: stuffed FF00, restart marker RST3, FF fill before a
	// stuffed byte, raw bytes that look like an EXIF signature, and a
	// byte sequence "FF 00 E1" that a naive marker scanner could
	// misread as APP1.
	scanData := []byte{
		0x11, 0x22, 0xFF, 0x00, 0x33, // stuffed 0xFF data byte
		0xFF, 0xD3, // RST3 restart marker
		0xFF, 0xFF, 0x00, 0x44, // FF fill + stuffed 0xFF
		'E', 'x', 'i', 'f', 0x00, 0x00, 0x99, // fake signature in scan
		0xFF, 0x00, 0xE1, // stuffed FF then data byte 0xE1
		0x55,
	}
	// After the scan: real EXIF segment #3 (removed) and a non-EXIF APP1
	// (kept), then EOI and trailing garbage after EOI (kept verbatim).
	app1Exif3 := makeSegment(0xE1, exifPayload)
	app1After := makeSegment(0xE1, []byte("not-exif-app1"))
	eoi := []byte{0xFF, 0xD9}
	trailer := []byte("TRAILING-BYTES")

	var input []byte
	input = append(input, soi...)
	input = append(input, app0...)
	input = append(input, app1XMP...)
	input = append(input, app1Exif1...)
	input = append(input, com...)
	input = append(input, app2...)
	input = append(input, exif2Padding...)
	input = append(input, app1Exif2...)
	input = append(input, sosHeader...)
	input = append(input, scanData...)
	input = append(input, app1Exif3...)
	input = append(input, app1After...)
	input = append(input, eoi...)
	input = append(input, trailer...)

	var want []byte
	want = append(want, soi...)
	want = append(want, app0...)
	want = append(want, app1XMP...)
	want = append(want, com...)
	want = append(want, app2...)
	want = append(want, exif2Padding...) // padding before deleted EXIF kept
	want = append(want, sosHeader...)
	want = append(want, scanData...)
	want = append(want, app1After...)
	want = append(want, eoi...)
	want = append(want, trailer...)

	got := scrubToString(t, input)
	if !bytes.Equal(got, want) {
		t.Fatalf("structural fixture mismatch:\n got % X\nwant % X", got, want)
	}

	// Idempotent on the structural fixture too.
	again := scrubToString(t, got)
	if !bytes.Equal(again, want) {
		t.Fatal("second scrub changed structural fixture output")
	}
}

// TestScrubErrors checks rejection of non-JPEG and truncated input, and
// that no output file is left behind on failure.
func TestScrubErrors(t *testing.T) {
	dir := t.TempDir()

	if err := ScrubJPEG(strings.NewReader("not a jpeg"), filepath.Join(dir, "a.jpg")); err == nil {
		t.Fatal("expected error for non-JPEG input")
	}
	// Truncated segment: APP0 claims a length beyond end of data.
	truncated := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x40, 0x01}
	if err := ScrubJPEG(bytes.NewReader(truncated), filepath.Join(dir, "b.jpg")); err == nil {
		t.Fatal("expected error for truncated segment")
	}
	// Truncated SOS header.
	truncSOS := []byte{0xFF, 0xD8, 0xFF, 0xDA, 0x00}
	if err := ScrubJPEG(bytes.NewReader(truncSOS), filepath.Join(dir, "c.jpg")); err == nil {
		t.Fatal("expected error for truncated SOS")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("no output file expected on error, found %d", len(entries))
	}
}
