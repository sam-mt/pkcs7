package pkcs7

import (
	"bytes"
	"compress/zlib"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
)

type compressedData struct {
	Version               int
	CompressionAlgorithm  pkix.AlgorithmIdentifier
	CompressedContentInfo compressedContentInfo
}

type compressedContentInfo struct {
	ContentType       asn1.ObjectIdentifier
	CompressedContent asn1.RawValue `asn1:"tag:0,optional"`
}

// ErrUnsupportedCompressionAlgorithm
var ErrUnsupportedCompressionAlgorithm = errors.New("pkcs7: cannot decompress data: only zlib is supported")

// ErrNotCompressedContent is returned when attempting to Decompress data that is not compressed data
var ErrNotCompressedContent = errors.New("pkcs7: content data is not compressed")

// Decompressed compressed data
func (p7 *PKCS7) Decompress() ([]byte, error) {
	data, ok := p7.raw.(compressedData)
	if !ok {
		return nil, ErrNotCompressedContent
	}

	var compressedContent []byte
	_, err := asn1.Unmarshal(data.CompressedContentInfo.CompressedContent.Bytes, &compressedContent)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal compressed content: %v", err)
	}
	contentReader := bytes.NewReader(compressedContent)

	switch {
	case data.CompressionAlgorithm.Algorithm.Equal(OIDCompressionAlgorithmZlib):
		zlibReader, err := zlib.NewReader(contentReader)
		if err != nil {
			return nil, fmt.Errorf("failed to create zlib reader: %v", err)
		}
		defer zlibReader.Close()

		decompressedData, err := io.ReadAll(zlibReader)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress data: %v", err)
		}

		return decompressedData, nil
	}

	return nil, ErrUnsupportedCompressionAlgorithm
}
