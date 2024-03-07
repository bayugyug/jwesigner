package jwesigner

import (
	"context"
	"crypto/rsa"
)

//go:generate mockgen -destination ./mock/mock_servicecreator.go -package mock github.com/bayugyug/jwesigner Creator

// Creator  ...
type Creator interface {
	Encrypt(ctx context.Context, message []byte) ([]byte, error)
	Decrypt(ctx context.Context, message []byte) ([]byte, error)
	Sign(ctx context.Context, message []byte) (string, error)
	Verify(ctx context.Context, signature string) (*Verified, error)

	SetOption(opts *Options)
	GetOption() *Options
	GetRSAPublicKey() *rsa.PublicKey
	GetRSAPrivateKey() *rsa.PrivateKey
}

// Service  ...
type Service struct {
	opts *Options
}

// New create a service
func New(opts *Options) Creator {
	// default
	svc := &Service{
		opts: opts,
	}

	return svc
}

// SetOption ...
func (s *Service) SetOption(opts *Options) {
	s.opts = opts
}

// GetOption ...
func (s *Service) GetOption() *Options {
	return s.opts
}

// GetRSAPublicKey ...
func (s *Service) GetRSAPublicKey() *rsa.PublicKey {
	k, _ := s.opts.GetRSAPublicKey()
	return k
}

// GetRSAPrivateKey ...
func (s *Service) GetRSAPrivateKey() *rsa.PrivateKey {
	k, _ := s.opts.GetRSAPrivateKey()
	return k
}
