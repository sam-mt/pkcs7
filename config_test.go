package pkcs7

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"testing"
)

func TestEncryptionConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    *EncryptionConfig
		wantError bool
	}{
		{
			name:      "valid default config",
			config:    DefaultConfig(),
			wantError: false,
		},
		{
			name:      "valid legacy config",
			config:    LegacyConfig(),
			wantError: false,
		},
		{
			name: "valid AES256CBC config",
			config: &EncryptionConfig{
				ContentEncryptionAlgorithm: EncryptionAlgorithmAES256CBC,
				KeyEncryptionAlgorithm:     OIDEncryptionAlgorithmRSAESOAEP,
				KeyEncryptionHash:          crypto.SHA512,
			},
			wantError: false,
		},
		{
			name: "invalid content encryption algorithm",
			config: &EncryptionConfig{
				ContentEncryptionAlgorithm: 999,
				KeyEncryptionAlgorithm:     OIDEncryptionAlgorithmRSA,
				KeyEncryptionHash:          crypto.SHA256,
			},
			wantError: true,
		},
		{
			name: "invalid key encryption algorithm",
			config: &EncryptionConfig{
				ContentEncryptionAlgorithm: EncryptionAlgorithmAES128GCM,
				KeyEncryptionAlgorithm:     asn1.ObjectIdentifier{1, 2, 3, 4, 5},
				KeyEncryptionHash:          crypto.SHA256,
			},
			wantError: true,
		},
		{
			name: "invalid key encryption hash",
			config: &EncryptionConfig{
				ContentEncryptionAlgorithm: EncryptionAlgorithmAES128GCM,
				KeyEncryptionAlgorithm:     OIDEncryptionAlgorithmRSA,
				KeyEncryptionHash:          crypto.Hash(999),
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Validate() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestNewEncryptionConfig(t *testing.T) {
	tests := []struct {
		name       string
		contentAlg int
		keyAlg     asn1.ObjectIdentifier
		hash       crypto.Hash
		wantError  bool
	}{
		{
			name:       "valid config",
			contentAlg: EncryptionAlgorithmAES256GCM,
			keyAlg:     OIDEncryptionAlgorithmRSAESOAEP,
			hash:       crypto.SHA256,
			wantError:  false,
		},
		{
			name:       "invalid content algorithm",
			contentAlg: 999,
			keyAlg:     OIDEncryptionAlgorithmRSA,
			hash:       crypto.SHA256,
			wantError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := NewEncryptionConfig(tt.contentAlg, tt.keyAlg, tt.hash)
			if (err != nil) != tt.wantError {
				t.Errorf("NewEncryptionConfig() error = %v, wantError %v", err, tt.wantError)
			}
			if !tt.wantError && config == nil {
				t.Error("NewEncryptionConfig() returned nil config but no error")
			}
		})
	}
}

func TestEncryptWithConfig(t *testing.T) {
	// Create a test certificate
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("Hello World with Config!")
	recipients := []*x509.Certificate{cert.Certificate}

	tests := []struct {
		name   string
		config *EncryptionConfig
	}{
		{
			name:   "default config",
			config: DefaultConfig(),
		},
		{
			name:   "legacy config",
			config: LegacyConfig(),
		},
		{
			name: "AES256CBC config",
			config: &EncryptionConfig{
				ContentEncryptionAlgorithm: EncryptionAlgorithmAES256CBC,
				KeyEncryptionAlgorithm:     OIDEncryptionAlgorithmRSA,
				KeyEncryptionHash:          crypto.SHA256,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := EncryptWithConfig(plaintext, recipients, tt.config)
			if err != nil {
				t.Fatalf("EncryptWithConfig() error = %v", err)
			}

			// Verify we can decrypt it
			p7, err := Parse(encrypted)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			result, err := p7.Decrypt(cert.Certificate, *cert.PrivateKey)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			if string(result) != string(plaintext) {
				t.Errorf("Decrypted content = %s, want %s", result, plaintext)
			}
		})
	}
}

func TestEncryptUsingPSKWithConfig(t *testing.T) {
	plaintext := []byte("Hello PSK World with Config!")

	tests := []struct {
		name   string
		config *EncryptionConfig
		key    []byte
	}{
		{
			name: "DES CBC with custom key",
			config: &EncryptionConfig{
				ContentEncryptionAlgorithm: EncryptionAlgorithmDESCBC,
				KeyEncryptionAlgorithm:     OIDEncryptionAlgorithmRSA,
				KeyEncryptionHash:          crypto.SHA256,
			},
			key: []byte("12345678"),
		},
		{
			name: "AES128 GCM with custom key",
			config: &EncryptionConfig{
				ContentEncryptionAlgorithm: EncryptionAlgorithmAES128GCM,
				KeyEncryptionAlgorithm:     OIDEncryptionAlgorithmRSA,
				KeyEncryptionHash:          crypto.SHA256,
			},
			key: []byte("1234567890123456"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := EncryptUsingPSKWithConfig(plaintext, tt.key, tt.config)
			if err != nil {
				t.Fatalf("EncryptUsingPSKWithConfig() error = %v", err)
			}

			// Verify we can decrypt it
			p7, err := Parse(encrypted)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			result, err := p7.DecryptUsingPSK(tt.key)
			if err != nil {
				t.Fatalf("DecryptUsingPSK() error = %v", err)
			}

			if string(result) != string(plaintext) {
				t.Errorf("Decrypted content = %s, want %s", result, plaintext)
			}
		})
	}
}

func TestEncryptWithConfig_NilConfig(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("Test")
	recipients := []*x509.Certificate{cert.Certificate}

	_, err = EncryptWithConfig(plaintext, recipients, nil)
	if err == nil || err.Error() != "pkcs7: encryption config cannot be nil" {
		t.Errorf("Expected nil config error, got: %v", err)
	}
}

func TestEncryptUsingPSKWithConfig_NilConfig(t *testing.T) {
	plaintext := []byte("Test")
	key := []byte("12345678")

	_, err := EncryptUsingPSKWithConfig(plaintext, key, nil)
	if err == nil || err.Error() != "pkcs7: encryption config cannot be nil" {
		t.Errorf("Expected nil config error, got: %v", err)
	}
}

func TestBackwardCompatibility(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("Backward compatibility test")
	recipients := []*x509.Certificate{cert.Certificate}

	// Test that old API still works exactly as before
	ContentEncryptionAlgorithm = EncryptionAlgorithmAES256CBC
	KeyEncryptionAlgorithm = OIDEncryptionAlgorithmRSAESOAEP
	KeyEncryptionHash = crypto.SHA384

	encrypted, err := Encrypt(plaintext, recipients)
	if err != nil {
		t.Fatal(err)
	}

	p7, err := Parse(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	result, err := p7.Decrypt(cert.Certificate, *cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	if string(result) != string(plaintext) {
		t.Errorf("Backward compatibility failed: got %s, want %s", result, plaintext)
	}
}
