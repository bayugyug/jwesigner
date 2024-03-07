package jwesigner

// Verified ...
type Verified struct {
	Payload   string `json:"payload,omitempty"`
	Protected string `json:"protected,omitempty"`
	Signature string `json:"signature,omitempty"`
	Full      string `json:"full,omitempty"`
	Compact   string `json:"compact,omitempty"`
	Data      string `json:"data,omitempty"`
}
