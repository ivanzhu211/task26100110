# VaultBrowse JPEG EXIF Scrubber

`ScrubJPEG` removes EXIF metadata from JPEG streams losslessly.

## Interface

```go
func ScrubJPEG(src io.Reader, dstPath string) error
```

- `src`: JPEG input stream (8-bit baseline or progressive, non-hierarchical;
  multiple SOS scans and application segments between/after scans supported).
- `dstPath`: local file path for the scrubbed result.

On success, `dstPath` contains exactly the input bytes minus every APP1
segment whose payload starts with `Exif\x00\x00` (marker, length field and
payload removed). The TIFF payload is never parsed, so corrupted EXIF
segments are still removed. All other bytes — non-EXIF APP1, ICC profiles,
comments, FF fill bytes, FF00 stuffed bytes, RSTn restart markers and
compressed image data — are preserved byte for byte. Scrubbing is
idempotent.

## Test

```sh
go test ./...
```
