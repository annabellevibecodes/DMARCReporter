package parser

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"path"
	"strings"
)

// maxDecompressedSize is the maximum allowed decompressed size (50 MB).
// DMARC aggregate reports are typically a few KB even for large deployments.
const maxDecompressedSize = 50 * 1024 * 1024

// IsDMARCFile returns true if the filename has a DMARC report extension.
func IsDMARCFile(filename string) bool {
	lower := strings.ToLower(filename)
	return strings.HasSuffix(lower, ".xml") ||
		strings.HasSuffix(lower, ".xml.gz") ||
		strings.HasSuffix(lower, ".gz") ||
		strings.HasSuffix(lower, ".zip")
}

// DetectAndDecompress inspects the filename and content to return a plain XML reader.
// Supported: .xml, .xml.gz, .gz, .xml.zip, .zip
func DetectAndDecompress(filename string, r io.Reader) (io.Reader, error) {
	// Buffer input (bounded by Fiber's BodyLimit or IMAP attachment limit upstream).
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}

	lower := strings.ToLower(filename)

	switch {
	case strings.HasSuffix(lower, ".xml"):
		return bytes.NewReader(data), nil
	case strings.HasSuffix(lower, ".gz"):
		return gunzip(data)
	case strings.HasSuffix(lower, ".zip"):
		return unzip(data)
	}

	// Unknown extension — try gzip, then zip, then treat as plain XML.
	if gr, err := gunzip(data); err == nil {
		return gr, nil
	}
	if zr, err := unzip(data); err == nil {
		return zr, nil
	}
	return bytes.NewReader(data), nil
}

func gunzip(data []byte) (io.Reader, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	limited := io.LimitReader(gr, maxDecompressedSize+1)
	out, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > maxDecompressedSize {
		return nil, fmt.Errorf("gzip decompressed content exceeds %d bytes", maxDecompressedSize)
	}
	return bytes.NewReader(out), nil
}

func unzip(data []byte) (io.Reader, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		// path.Base strips any directory components from the entry name,
		// preventing path traversal sequences (e.g. ../../evil.xml).
		lower := strings.ToLower(path.Base(f.Name))
		if !strings.HasSuffix(lower, ".xml") && !strings.HasSuffix(lower, ".xml.gz") {
			continue
		}
		// Reject zip entries claiming to be too large before opening.
		if f.UncompressedSize64 > uint64(maxDecompressedSize) {
			return nil, fmt.Errorf("zip entry %q claims uncompressed size %d, exceeds limit",
				f.Name, f.UncompressedSize64)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		limited := io.LimitReader(rc, maxDecompressedSize+1)
		out, err := io.ReadAll(limited)
		if err != nil {
			return nil, err
		}
		if int64(len(out)) > maxDecompressedSize {
			return nil, fmt.Errorf("zip entry decompressed content exceeds %d bytes", maxDecompressedSize)
		}
		if strings.HasSuffix(lower, ".gz") {
			return gunzip(out)
		}
		return bytes.NewReader(out), nil
	}
	return nil, fmt.Errorf("no XML file found in zip archive")
}
