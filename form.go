package jwesigner

import (
	"fmt"
	"github.com/google/uuid"
	"strings"
	"time"
)

// FormOpts ...
type FormOpts struct {
	Auth      string
	SignUUID  string
	Timestamp int64
	Method    string
	Link      string
	Payload   []byte
	Sep       string
}

//
//			auth-key | sign-uuid | timestamp | URI | payload
//
// FormatPayloadToSign ...
func FormatPayloadToSign(opts *FormOpts) string {
	if opts == nil {
		opts = NewOpts()
	}
	if len(opts.SignUUID) <= 0 {
		opts.SignUUID = uuid.NewString()
	}
	if opts.Timestamp <= 0 {
		opts.Timestamp = time.Now().UTC().Unix()
	}
	sep := CaretB
	if len(opts.Sep) > 0 {
		sep = opts.Sep
	}
	return strings.TrimSpace(
		fmt.Sprintf("%s%s%s%s%d%s%s%s%s",
			opts.Auth, sep,
			opts.SignUUID, sep,
			opts.Timestamp, sep,
			opts.Link, sep,
			opts.Payload,
		),
	)
}

// NewOpts ...
func NewOpts() *FormOpts {
	return &FormOpts{
		SignUUID:  uuid.NewString(),
		Timestamp: time.Now().UTC().Unix(),
	}
}
