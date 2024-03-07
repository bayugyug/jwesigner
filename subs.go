package jwesigner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	jose "github.com/go-jose/go-jose/v3"
)

// Encrypt ... encrypt with their public-key
func (s *Service) Encrypt(ctx context.Context, message []byte) ([]byte, error) {

	var (
		publicKey, _ = s.opts.GetRSAPublicKey()
		alg          = jose.RSA_OAEP_256
		enc          = jose.A256GCM
	)

	encrypter, err := jose.NewEncrypter(enc, jose.Recipient{Algorithm: alg, Key: publicKey}, nil)
	if err != nil {
		return nil, fmt.Errorf("error encrypt: %v", err.Error())
	}

	object, err := encrypter.Encrypt(message)
	if err != nil {
		return nil, fmt.Errorf("error encrypt: %v", err.Error())
	}

	serialized, _ := object.CompactSerialize()

	// good ;-)
	return []byte(serialized), nil
}

// Decrypt ... decrypt with our private-key
func (s *Service) Decrypt(ctx context.Context, message []byte) ([]byte, error) {
	var (
		private, _ = s.opts.GetRSAPrivateKey()
	)

	decrypter, err := jose.ParseEncrypted(string(message))
	if err != nil {
		return nil, fmt.Errorf("error decrypt: unable to parse message %v", err.Error())
	}

	decrypted, err := decrypter.Decrypt(private)
	if err != nil {
		return nil, fmt.Errorf("error decrypt: unable to decrypt message %v", err.Error())
	}

	// good ;-)
	return decrypted, nil
}

// Sign ... sign with our private key
func (s *Service) Sign(ctx context.Context, message []byte) (string, error) {

	var (
		private, _ = s.opts.GetRSAPrivateKey()
		alg        = jose.RS256
	)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: private}, nil)
	if err != nil {
		return "", fmt.Errorf("error sign: %v", err.Error())
	}

	obj, err := signer.Sign(message)
	if err != nil {
		return "", fmt.Errorf("error sign: %v", err.Error())
	}

	signature, _ := obj.CompactSerialize()

	// good ;-)
	return signature, nil
}

// Verify ... decrypt with our private key & verify it with their public key
func (s *Service) Verify(ctx context.Context, signature string) (*Verified, error) {

	var (
		publicKey, _ = s.opts.GetRSAPublicKey()
		result       Verified
	)

	obj, err := jose.ParseSigned(signature)
	if err != nil {
		return nil, fmt.Errorf("error verify: unable to parse message %v", err.Error())
	}

	if _, e := obj.Verify(publicKey); e != nil {
		return nil, fmt.Errorf("error verify: invalid signature %v", e.Error())
	}

	var (
		compact, _ = obj.CompactSerialize()
		full       = obj.FullSerialize()
	)
	// init
	result = Verified{
		Full:    full,
		Compact: compact,
	}

	// add more
	if e := json.Unmarshal([]byte(full), &result); e != nil {
		return nil, fmt.Errorf("error verify: invalid data %v", e.Error())
	}

	// decode
	if len(result.Payload) > 0 {
		b, _ := base64.RawStdEncoding.DecodeString(result.Payload)
		result.Data = string(b)
	}

	// good ;-)
	return &result, nil
}
