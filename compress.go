package pkcs7

import (
	"bytes"
	"compress/zlib"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// Compress compresses data using zlib and wraps it in a PKCS#7 CompressedData
// structure (OID 1.2.840.113549.1.9.16.1.9, RFC 3274).
func Compress(data []byte) ([]byte, error) {
	buf := bytes.Buffer{}

	zlibWriter := zlib.NewWriter(&buf)
	if _, err := zlibWriter.Write(data); err != nil {
		return nil, fmt.Errorf("failed to compress data: %w", err)
	}
	if err := zlibWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalise zlib stream: %w", err)
	}

	octets, err := asn1.Marshal(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal compressed content: %w", err)
	}
	compressedData := compressedData{
		Version: 0,
		CompressionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: OIDCompressionAlgorithmZlib,
		},
		CompressedContentInfo: contentInfo{
			ContentType: OIDData,
			Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: octets},
		},
	}

	innerContent, err := asn1.Marshal(compressedData)
	if err != nil {
		return nil, err
	}

	wrapper := contentInfo{
		ContentType: OIDCompressedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: innerContent},
	}

	return asn1.Marshal(wrapper)
}
