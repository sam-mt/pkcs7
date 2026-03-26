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
	CompressedContentInfo contentInfo
}

// ErrUnsupportedCompressionAlgorithm
var ErrUnsupportedCompressionAlgorithm = errors.New("pkcs7: cannot decompress data: only zlib is supported")

// ErrNotCompressedContent is returned when attempting to Decompress data that is not compressed data
var ErrNotCompressedContent = errors.New("pkcs7: content data is not compressed")

// unmarshalOctetStringContent extracts the raw byte content from an ASN.1 OCTET STRING
// encoded in either primitive form (DER, tag 0x04) or constructed form (BER, tag 0x24).
// Senders such as Axway legitimately produce the constructed form.
// Go's encoding/asn1 rejects constructed OCTET STRINGs when decoding into []byte,
// so we handle both forms explicitly here.
func unmarshalOctetStringContent(b []byte) ([]byte, error) {
	// Use asn1.RawValue so we can inspect the tag without having asn1.Unmarshal
	// reject the constructed form.
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(b, &raw); err != nil {
		return nil, err
	}

	if raw.Tag != asn1.TagOctetString {
		return nil, fmt.Errorf("expected OCTET STRING (tag %d), got tag %d", asn1.TagOctetString, raw.Tag)
	}

	if !raw.IsCompound {
		// Primitive form – raw.Bytes is the content directly.
		return raw.Bytes, nil
	}

	// Constructed (segmented) OCTET STRING: concatenate the bytes of all
	// inner primitive OCTET STRING fragments.
	var out []byte
	inner := raw.Bytes
	for len(inner) > 0 {
		var frag asn1.RawValue
		rest, err := asn1.Unmarshal(inner, &frag)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal OCTET STRING fragment: %v", err)
		}
		if frag.Tag != asn1.TagOctetString {
			return nil, fmt.Errorf("unexpected tag %d in constructed OCTET STRING, expected OCTET STRING (tag %d)", frag.Tag, asn1.TagOctetString)
		}
		out = append(out, frag.Bytes...)
		inner = rest
	}
	return out, nil
}

// Decompress decompresses PKCS#7 CompressedData content. Only zlib
// (OIDCompressionAlgorithmZlib) is supported; any other algorithm returns
// ErrUnsupportedCompressionAlgorithm.
func (p7 *PKCS7) Decompress() ([]byte, error) {
	data, ok := p7.raw.(compressedData)
	if !ok {
		return nil, ErrNotCompressedContent
	}

	compressedContent, err := unmarshalOctetStringContent(data.CompressedContentInfo.Content.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal compressed content: %v", err)
	}

	if !data.CompressionAlgorithm.Algorithm.Equal(OIDCompressionAlgorithmZlib) {
		return nil, ErrUnsupportedCompressionAlgorithm
	}

	contentReader := bytes.NewReader(compressedContent)
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
