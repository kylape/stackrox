//go:build test_e2e || test_compatibility

package tests

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/testutils/centralgrpc"
	"google.golang.org/grpc"
)

var _ = Describe("AuthService", Label("BAT", "COMPATIBILITY"), func() {
	var (
		conn        *grpc.ClientConn
		authService v1.AuthServiceClient
		ctx         context.Context
	)

	BeforeEach(func() {
		// Create gRPC connection using existing infrastructure
		conn = centralgrpc.GRPCConnectionToCentral(GinkgoT())
		authService = v1.NewAuthServiceClient(conn)
		ctx = context.Background()

		// Cleanup connection after each test
		DeferCleanup(func() {
			if conn != nil {
				conn.Close()
			}
		})
	})

	Context("Basic Authentication", func() {
		It("should return valid auth status for admin user", func() {
			By("When getting auth status with basic auth")
			status, err := authService.GetAuthStatus(ctx, &v1.Empty{})
			Expect(err).NotTo(HaveOccurred())

			By("Then the response should contain admin user info")
			Expect(status).NotTo(BeNil())
			Expect(status.GetUserId()).To(Equal("admin"))

			By("And the auth provider should be basic auth")
			authProvider := status.GetAuthProvider()
			Expect(authProvider).NotTo(BeNil())
			Expect(authProvider.GetName()).To(Equal("Login with username/password"))
			Expect(authProvider.GetId()).To(Equal("4df1b98c-24ed-4073-a9ad-356aec6bb62d"))
			Expect(authProvider.GetType()).To(Equal("basic"))

			By("And the user should have admin permissions")
			userInfo := status.GetUserInfo()
			Expect(userInfo).NotTo(BeNil())

			permissions := userInfo.GetPermissions()
			Expect(permissions.GetResourceToAccess()).NotTo(BeEmpty())

			// Verify all resources have READ_WRITE_ACCESS
			for _, access := range permissions.GetResourceToAccess() {
				Expect(access).To(Equal(storage.Access_READ_WRITE_ACCESS))
			}

			// Verify admin role exists
			roles := userInfo.GetRoles()
			var foundAdminRole bool
			for _, role := range roles {
				if role.GetName() == "Admin" {
					foundAdminRole = true
					break
				}
			}
			Expect(foundAdminRole).To(BeTrue(), "Admin role should exist")

			By("And user attributes should contain correct username and role")
			attrMap := makeAttributeMap(status.GetUserAttributes())
			Expect(attrMap).To(HaveKey("username"))
			Expect(attrMap["username"]).To(ContainElement("admin"))
			Expect(attrMap).To(HaveKey("role"))
			Expect(attrMap["role"]).To(ContainElement("Admin"))
		})
	})

	// Note: The "auth token" test from Groovy requires token generation setup
	// which depends on BaseSpecification.useTokenServiceAuth()
	// We'll implement this once we understand the token generation flow better
	PContext("API Token Authentication", func() {
		It("should return valid auth status for API token", func() {
			Skip("Requires token generation infrastructure - to be implemented")
		})
	})
})

// makeAttributeMap converts the UserAttribute list to a map of key -> values
// This mirrors the getAttrMap helper from the Groovy test
func makeAttributeMap(attrs []*v1.UserAttribute) map[string][]string {
	result := make(map[string][]string)
	for _, attr := range attrs {
		result[attr.GetKey()] = attr.GetValues()
	}
	return result
}
