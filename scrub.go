// Package vaultbrowse provides JPEG EXIF scrubbing for VaultBrowse.
package vaultbrowse

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

// exifSignature is the APP1 payload prefix identifying an EXIF segment:
// ASCII "Exif" followed by two zero bytes.
var exifSignature = []byte("Exif\x00\x00")

// ScrubJPEG reads a JPEG stream from src, removes every APP1 segment whose
// payload begins with the "Exif\x00\x00" signature (marker, length field and
// payload are all dropped), and writes the result to the local file dstPath.
//
// All other bytes are preserved verbatim: non-EXIF APP1 segments, ICC
// profiles, comments, FF fill bytes preceding markers, FF00 stuffed bytes and
// RSTn restart markers inside scan data, and the compressed image data
// itself. The TIFF payload of EXIF segments is never parsed, so corrupted
// EXIF segments are still removed.
//
// It supports non-hierarchical 8-bit baseline and progressive JPEGs,
// including multiple SOS scans, application segments between scans, and
// application segments after the final scan.
func ScrubJPEG(src io.Reader, dstPath string) error {
	data, err := io.ReadAll(src)
	if err != nil {
		return fmt.Errorf("scrubjpeg: reading source: %w", err)
	}
	out, err := scrubEXIF(data)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dstPath, out, 0o644); err != nil {
		return fmt.Errorf("scrubjpeg: writing %s: %w", dstPath, err)
	}
	return nil
}

// scrubEXIF returns data with all EXIF APP1 segments removed.
func scrubEXIF(data []byte) ([]byte, error) {
	var out bytes.Buffer
	out.Grow(len(data))

	i := 0
	inScan := false
	for i < len(data) {
		b := data[i]
		if b != 0xFF {
			// Entropy-coded data (in scan) or leading garbage: copy verbatim.
			out.WriteByte(b)
			i++
			continue
		}
		// b == 0xFF: a marker candidate. Find the marker code, copying
		// any fill 0xFF bytes verbatim.
		out.WriteByte(0xFF)
		i++
		for i < len(data) && data[i] == 0xFF {
			out.WriteByte(0xFF)
			i++
		}
		if i >= len(data) {
			return nil, errors.New("scrubjpeg: truncated at fill bytes")
		}
		marker := data[i]

		if inScan {
			switch {
			case marker == 0x00:
				// FF00 byte stuffing: literal 0xFF data byte.
				out.WriteByte(0x00)
				i++
				continue
			case marker >= 0xD0 && marker <= 0xD7:
				// RST0-RST7 restart marker: part of scan data.
				out.WriteByte(marker)
				i++
				continue
			default:
				// Any other marker terminates the scan. Do not
				// consume it here; fall through to header handling.
				inScan = false
			}
		}

		switch {
		case marker == 0x00:
			// Stray FF00 outside a scan: keep verbatim.
			out.WriteByte(0x00)
			i++
		case marker == 0x01 || marker == 0xD8 ||
			(marker >= 0xD0 && marker <= 0xD7):
			// Standalone markers without a length field: TEM, SOI, RSTn.
			out.WriteByte(marker)
			i++
		case marker == 0xD9:
			// EOI: end of image. Copy everything that follows verbatim
			// (trailing data is not part of the marker stream).
			out.WriteByte(marker)
			i++
			out.Write(data[i:])
			i = len(data)
		default:
			// Marker with a 2-byte big-endian length field that
			// includes the length bytes themselves.
			if i+3 > len(data) {
				return nil, fmt.Errorf("scrubjpeg: truncated length after marker FF%02X", marker)
			}
			segLen := int(data[i+1])<<8 | int(data[i+2])
			if segLen < 2 {
				return nil, fmt.Errorf("scrubjpeg: invalid segment length %d after marker FF%02X", segLen, marker)
			}
			segEnd := i + 1 + segLen
			if segEnd > len(data) {
				return nil, fmt.Errorf("scrubjpeg: truncated segment after marker FF%02X", marker)
			}
			payload := data[i+3 : segEnd]
			if marker == 0xE1 && bytes.HasPrefix(payload, exifSignature) {
				// EXIF APP1: drop marker, length and payload.
				// The 0xFF already written is the marker's own FF,
				// so remove it from the output as well.
				out.Truncate(out.Len() - 1)
			} else {
				out.Write(data[i:segEnd])
			}
			if marker == 0xDA {
				// SOS: entropy-coded scan data follows.
				inScan = true
			}
			i = segEnd
		}
	}
	return out.Bytes(), nil
}
