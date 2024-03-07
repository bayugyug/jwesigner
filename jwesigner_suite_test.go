package jwesigner_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestJwesigner(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Jwesigner Suite")
}
