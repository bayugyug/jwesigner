package jwesigner

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/bayugyug/authorizer/commons"
	"github.com/golang-jwt/jwt/v4"
)

//
//	PublicKey
//			remote public key ( client )
//			used for verifying, the signature of the remote client
//			shared by client to us
//			is the public key pair of the remote client
//
//			use to encrypt data ( send to remote client )
//
//	PrivateKey
//			own local private key ( SELF )
//			used for signing
//			the remote client will verify it using the public key of this private key
//			we will share the public key pair to the remote client
//
//			use to decrypt encrypted data ( sent by remote client )
//
//  Separator
//
//			
//
//
//		_____________________________
//		For REMOTE-CLIENT calling YOUR-APIs
//
//		We  go with JWE and JWS on payload
//		_____________________________
//
//		#REQUEST
//		1.    REMOTE-CLIENT perform  Sign on request using REMOTE-CLIENT  Private key
//		2.    REMOTE-CLIENT Encrypt  request Payload using  YOUR Public key
//		3.    YOU decrypt the Payload using YOU private key
//		4.    YOU verify  sign  using REMOTE-CLIENT public key
//
//		#RESPONSE
//		5.    YOU perform   Sign  on response  using  YOUR private key
//		6.    YOU encrypt  the response  Payload using REMOTE-CLIENT public key
//		7.    REMOTE-CLIENT decrypt the response Payload using REMOTE-CLIENT private key
//		8.    REMOTE-CLIENT verify  Sign on response   using YOU public key
//
//			Sign Algorithm
//			RS256
//
//			Encryption & Decryption Algorithm
//			RSA_OAEP_256
//
//

var (
	// CaretB ...
	CaretB = ""
)

// Options ...
type Options struct {
	PrivateKey string
	PublicKey  string
}

var (
	// ErrMissingParams ...
	ErrMissingParams = errors.New("missing required parameters")
)

// OptArgs options ...
type OptArgs func(*Options)

// WithPrivateKey ...
func WithPrivateKey(param string) OptArgs {
	return func(args *Options) {
		args.PrivateKey = param
	}
}

// WithPublicKey ...
func WithPublicKey(param string) OptArgs {
	return func(args *Options) {
		args.PublicKey = param
	}
}

// GetRSAPrivateKey ...
func (k *Options) GetRSAPrivateKey() (*rsa.PrivateKey, error) {
	return jwt.ParseRSAPrivateKeyFromPEM([]byte(commons.FormatConfigFromEnvt(k.PrivateKey)))
}

// GetRSAPublicKey ...
func (k *Options) GetRSAPublicKey() (*rsa.PublicKey, error) {
	return jwt.ParseRSAPublicKeyFromPEM([]byte(commons.FormatConfigFromEnvt(k.PublicKey)))
}

// GetPublicKeyPKCS ...
func (k *Options) GetPublicKeyPKCS() (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(commons.FormatConfigFromEnvt(k.PublicKey)))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub, nil
}
