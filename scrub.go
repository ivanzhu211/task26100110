// Package vaultbrowse provides JPEG lossless EXIF scrubbing for VaultBrowse.
package vaultbrowse

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// exifSignature is the APP1 payload prefix identifying an EXIF segment.
var exifSignature = []byte("Exif\x00\x00")

// ScrubJPEG reads a JPEG stream from src and writes the result to dstPath
// with every APP1 segment whose payload begins with "Exif\x00\x00" removed
// (marker, length field and full payload). All other bytes, including FF
// padding before markers, non-EXIF APP1 segments and compressed scan data,
// are preserved byte for byte.
func ScrubJPEG(src io.Reader, dstPath string) error {
	data, err := io.ReadAll(src)
	if err != nil {
		return fmt.Errorf("scrubjpeg: read source: %w", err)
	}
	out, err := scrubEXIF(data)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dstPath, out, 0o644); err != nil {
		return fmt.Errorf("scrubjpeg: write %s: %w", dstPath, err)
	}
	return nil
}

// scrubEXIF returns data with all EXIF APP1 segments removed.
func scrubEXIF(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != 0xFF || data[1] != 0xD8 {
		return nil, errors.New("scrubjpeg: missing SOI marker")
	}
	out := make([]byte, 0, len(data))
	out = append(out, data[0], data[1])
	pos := 2

	for pos < len(data) {
		// Collect the run of 0xFF bytes preceding a marker. All but the
		// last are padding and must be preserved even for deleted segments.
		ffStart := pos
		for pos < len(data) && data[pos] == 0xFF {
			pos++
		}
		if pos >= len(data) {
			// Trailing padding with no marker: copy verbatim.
			out = append(out, data[ffStart:pos]...)
			break
		}
		marker := data[pos]
		pos++

		if marker == 0xE1 && isEXIFSegment(data, pos) {
			// Drop the marker's own 0xFF plus marker, length and payload;
			// keep any extra padding FFs before it.
			out = append(out, data[ffStart:pos-1-1]...)
			segLen := int(binary.BigEndian.Uint16(data[pos:]))
			pos += segLen
			continue
		}

		out = append(out, data[ffStart:pos]...)

		switch {
		case marker == 0x00 || marker == 0x01 ||
			(marker >= 0xD0 && marker <= 0xD8):
			// Standalone markers without a length field: 0x00 should not
			// appear here but is copied defensively; 0x01 TEM; 0xD0-0xD7
			// RSTn; 0xD8 SOI.
		case marker == 0xD9: // EOI: anything after is copied verbatim.
			out = append(out, data[pos:]...)
			pos = len(data)
		case marker == 0xDA: // SOS: header followed by entropy-coded data.
			segLen, err := segmentLength(data, pos)
			if err != nil {
				return nil, err
			}
			out = append(out, data[pos:pos+segLen]...)
			pos += segLen
			scanEnd, err := skipScanData(data, pos)
			if err != nil {
				return nil, err
			}
			out = append(out, data[pos:scanEnd]...)
			pos = scanEnd
		default:
			// All other markers carry a 2-byte length field.
			segLen, err := segmentLength(data, pos)
			if err != nil {
				return nil, err
			}
			out = append(out, data[pos:pos+segLen]...)
			pos += segLen
		}
	}
	return out, nil
}

// isEXIFSegment reports whether the segment whose length field starts at
// data[pos] is an APP1 segment with the EXIF signature. It only inspects the
// length and payload prefix; the TIFF payload itself is never parsed.
func isEXIFSegment(data []byte, pos int) bool {
	if pos+2 > len(data) {
		return false
	}
	segLen := int(binary.BigEndian.Uint16(data[pos:]))
	if segLen < 2+len(exifSignature) || pos+segLen > len(data) {
		return false
	}
	return bytes.Equal(data[pos+2:pos+2+len(exifSignature)], exifSignature)
}

// segmentLength reads the big-endian length field at data[pos] and validates
// that the whole segment lies within data.
func segmentLength(data []byte, pos int) (int, error) {
	if pos+2 > len(data) {
		return 0, errors.New("scrubjpeg: truncated segment length field")
	}
	segLen := int(binary.BigEndian.Uint16(data[pos:]))
	if segLen < 2 {
		return 0, fmt.Errorf("scrubjpeg: invalid segment length %d", segLen)
	}
	if pos+segLen > len(data) {
		return 0, errors.New("scrubjpeg: segment extends past end of data")
	}
	return segLen, nil
}

// skipScanData returns the offset just past the entropy-coded scan data that
// begins at pos. The returned offset points at the 0xFF of the next real
// marker (or the start of its FF padding run). FF00 byte stuffing, RST0-RST7
// restart markers and FF fill bytes are treated as scan data.
func skipScanData(data []byte, pos int) (int, error) {
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
			// FF padding at end of data with no following marker.
			return pos, nil
		}
		next := data[runEnd]
		if next == 0x00 || (next >= 0xD0 && next <= 0xD7) {
			// Stuffed 0xFF data byte or restart marker: part of the scan.
			pos = runEnd + 1
			continue
		}
		// A real marker terminates the scan. Leave the whole FF run for
		// the marker parser so padding is preserved.
		return pos, nil
	}
	return pos, nil
}
