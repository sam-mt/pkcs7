package pkcs7

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

// TestCompressDecompressRoundTrip verifies that Compress followed by
// Parse + Decompress recovers the original plaintext.
func TestCompressDecompressRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("Hello, World!")},
		{"binary", func() []byte {
			b := make([]byte, 256)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}()},
		{"repetitive 4KB", bytes.Repeat([]byte("abcdefgh"), 512)},
		{"random-ish 1KB", func() []byte {
			b := make([]byte, 1024)
			for i := range b {
				b[i] = byte((i*31 + 7) % 256)
			}
			return b
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := Compress(tt.payload)
			if err != nil {
				t.Fatalf("Compress() error = %v", err)
			}
			if len(compressed) == 0 {
				t.Fatal("Compress() returned empty output")
			}

			p7, err := Parse(compressed)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			got, err := p7.Decompress()
			if err != nil {
				t.Fatalf("Decompress() error = %v", err)
			}

			if !bytes.Equal(tt.payload, got) {
				t.Errorf("round-trip mismatch: got %d bytes, want %d bytes", len(got), len(tt.payload))
			}
		})
	}
}

// TestDecompress_NotCompressedContent verifies that calling Decompress on a
// non-CompressedData PKCS7 structure returns ErrNotCompressedContent.
func TestDecompress_NotCompressedContent(t *testing.T) {
	// Build a minimal envelopedData shell — any non-compressedData raw type will do.
	p7 := &PKCS7{raw: envelopedData{}}
	_, err := p7.Decompress()
	if err != ErrNotCompressedContent {
		t.Errorf("expected ErrNotCompressedContent, got %v", err)
	}
}

// TestDecompress_UnsupportedAlgorithm verifies that an unknown compression
// algorithm OID returns ErrUnsupportedCompressionAlgorithm.
func TestDecompress_UnsupportedAlgorithm(t *testing.T) {
	// Build a valid payload using our Compress helper, then swap the algorithm OID.
	raw, err := Compress([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Overwrite the algorithm with an unknown OID.
	cd := p7.raw.(compressedData)
	cd.CompressionAlgorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	p7.raw = cd

	_, err = p7.Decompress()
	if err != ErrUnsupportedCompressionAlgorithm {
		t.Errorf("expected ErrUnsupportedCompressionAlgorithm, got %v", err)
	}
}

// TestUnmarshalOctetStringContent_Primitive tests the normal DER primitive form.
func TestUnmarshalOctetStringContent_Primitive(t *testing.T) {
	payload := []byte("hello")
	// Marshal as a standard primitive OCTET STRING.
	encoded, err := asn1.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unmarshalOctetStringContent(encoded)
	if err != nil {
		t.Fatalf("unmarshalOctetStringContent() error = %v", err)
	}
	if !bytes.Equal(payload, got) {
		t.Errorf("got %v, want %v", got, payload)
	}
}

// TestUnmarshalOctetStringContent_Constructed tests the BER constructed
// (segmented) form, which is produced by senders like Axway.
func TestUnmarshalOctetStringContent_Constructed(t *testing.T) {
	frag1 := []byte("hello")
	frag2 := []byte(", world")

	// Encode each fragment as a primitive OCTET STRING.
	enc1, _ := asn1.Marshal(frag1)
	enc2, _ := asn1.Marshal(frag2)
	inner := append(enc1, enc2...)

	// Build a constructed OCTET STRING (class=Universal, tag=4, compound=true).
	constructed := asn1.RawValue{
		Tag:        asn1.TagOctetString,
		IsCompound: true,
		Bytes:      inner,
	}
	encoded, err := asn1.Marshal(constructed)
	if err != nil {
		t.Fatal(err)
	}

	got, err := unmarshalOctetStringContent(encoded)
	if err != nil {
		t.Fatalf("unmarshalOctetStringContent() error = %v", err)
	}

	want := append(frag1, frag2...)
	if !bytes.Equal(want, got) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestUnmarshalOctetStringContent_WrongOuterTag verifies that a non-OCTET-STRING
// outer tag is rejected.
func TestUnmarshalOctetStringContent_WrongOuterTag(t *testing.T) {
	// Encode as an INTEGER instead of an OCTET STRING.
	encoded, err := asn1.Marshal(42)
	if err != nil {
		t.Fatal(err)
	}
	_, err = unmarshalOctetStringContent(encoded)
	if err == nil {
		t.Error("expected error for wrong outer tag, got nil")
	}
}

// TestUnmarshalOctetStringContent_WrongFragmentTag verifies that a fragment with
// a tag other than OCTET STRING inside a constructed OCTET STRING is rejected.
// This is the bug we fixed: previously the bytes were silently accepted.
func TestUnmarshalOctetStringContent_WrongFragmentTag(t *testing.T) {
	// Build a fragment encoded as an INTEGER (tag 2) instead of OCTET STRING.
	badFrag, _ := asn1.Marshal(99) // INTEGER

	constructed := asn1.RawValue{
		Tag:        asn1.TagOctetString,
		IsCompound: true,
		Bytes:      badFrag,
	}
	encoded, err := asn1.Marshal(constructed)
	if err != nil {
		t.Fatal(err)
	}

	_, err = unmarshalOctetStringContent(encoded)
	if err == nil {
		t.Error("expected error for non-OCTET-STRING fragment tag, got nil")
	}
}

// TestUnmarshalOctetStringContent_Empty verifies that an empty primitive OCTET
// STRING is handled without error and returns an empty slice.
func TestUnmarshalOctetStringContent_Empty(t *testing.T) {
	encoded, err := asn1.Marshal([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := unmarshalOctetStringContent(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %v", got)
	}
}
