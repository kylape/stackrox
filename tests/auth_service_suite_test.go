//go:build test_e2e || test_compatibility

package tests

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestAuthService(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "AuthService Suite")
}
