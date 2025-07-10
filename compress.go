package pkcs7

import (
	"bytes"
	"compress/zlib"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

func Compress(data []byte) ([]byte, error) {
	buf := bytes.Buffer{}

	zlibWriter := zlib.NewWriter(&buf)
	if _, err := zlibWriter.Write(data); err != nil {
		return nil, fmt.Errorf("failed to compress data: %w", err)
	}
	zlibWriter.Close()

	octets, _ := asn1.Marshal(buf.Bytes())
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
