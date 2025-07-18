//go:build sql_integration

package resolvers

import (
	"context"
	"testing"

	"github.com/graph-gophers/graphql-go"
	"github.com/stackrox/rox/central/graphql/resolvers/loaders"
	deploymentsView "github.com/stackrox/rox/central/views/deployments"
	"github.com/stackrox/rox/central/views/imagecomponentflat"
	"github.com/stackrox/rox/central/views/imagecveflat"
	imagesView "github.com/stackrox/rox/central/views/images"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/features"
	"github.com/stackrox/rox/pkg/fixtures/fixtureconsts"
	"github.com/stackrox/rox/pkg/grpc/authz/allow"
	"github.com/stackrox/rox/pkg/postgres/pgtest"
	"github.com/stackrox/rox/pkg/sac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
)

const (
	comp11 = "comp1image1"
	comp12 = "comp1image2"
	comp21 = "comp2image1"
	comp31 = "comp3image1"
	comp32 = "comp3image2"
	comp42 = "comp4image2"
)

func TestGraphQLImageComponentV2Endpoints(t *testing.T) {
	suite.Run(t, new(GraphQLImageComponentV2TestSuite))
}

/*
Remaining TODO tasks:
- as sub resolver
	- from clusters
	- from namespace
- sub resolvers
	- ActiveState
	- LastScanned
	- LayerIndex
	- Location
*/

type GraphQLImageComponentV2TestSuite struct {
	suite.Suite

	ctx            context.Context
	testDB         *pgtest.TestPostgres
	resolver       *Resolver
	componentIDMap map[string]string
}

func (s *GraphQLImageComponentV2TestSuite) SetupSuite() {
	if !features.FlattenCVEData.Enabled() {
		s.T().Skip()
	}

	s.ctx = loaders.WithLoaderContext(sac.WithAllAccess(context.Background()))
	mockCtrl := gomock.NewController(s.T())
	s.testDB = pgtest.ForT(s.T())
	imageDataStore := CreateTestImageV2Datastore(s.T(), s.testDB, mockCtrl)
	resolver, _ := SetupTestResolver(s.T(),
		imagesView.NewImageView(s.testDB.DB),
		imageDataStore,
		CreateTestImageComponentV2Datastore(s.T(), s.testDB, mockCtrl),
		CreateTestImageCVEV2Datastore(s.T(), s.testDB),
		CreateTestDeploymentDatastore(s.T(), s.testDB, mockCtrl, imageDataStore),
		deploymentsView.NewDeploymentView(s.testDB.DB),
		imagecveflat.NewCVEFlatView(s.testDB.DB),
		imagecomponentflat.NewComponentFlatView(s.testDB.DB),
	)
	s.resolver = resolver

	// Add Test Data to DataStores
	testDeployments := testDeployments()
	for _, dep := range testDeployments {
		err := s.resolver.DeploymentDataStore.UpsertDeployment(s.ctx, dep)
		s.NoError(err)
	}

	testImages := testImagesWithOperatingSystems()
	for _, image := range testImages {
		err := s.resolver.ImageDataStore.UpsertImage(s.ctx, image)
		s.NoError(err)
	}

	s.componentIDMap = s.getComponentIDMap()
}

func (s *GraphQLImageComponentV2TestSuite) TearDownSuite() {

	s.T().Setenv("ROX_FLATTEN_CVE_DATA", "false")
}

func (s *GraphQLImageComponentV2TestSuite) TestUnauthorizedImageComponentEndpoint() {
	_, err := s.resolver.ImageComponent(s.ctx, IDQuery{})
	assert.Error(s.T(), err, "Unauthorized request got through")
}

func (s *GraphQLImageComponentV2TestSuite) TestUnauthorizedImageComponentsEndpoint() {
	_, err := s.resolver.ImageComponents(s.ctx, PaginatedQuery{})
	assert.Error(s.T(), err, "Unauthorized request got through")
}

func (s *GraphQLImageComponentV2TestSuite) TestUnauthorizedImageComponentCountEndpoint() {
	_, err := s.resolver.ImageComponentCount(s.ctx, RawQuery{})
	assert.Error(s.T(), err, "Unauthorized request got through")
}

func (s *GraphQLImageComponentV2TestSuite) TestImageComponents() {
	ctx := SetAuthorizerOverride(s.ctx, allow.Anonymous())

	expectedIDs := []string{
		s.componentIDMap[comp11],
		s.componentIDMap[comp12],
		s.componentIDMap[comp21],
		s.componentIDMap[comp31],
		s.componentIDMap[comp32],
		s.componentIDMap[comp42],
	}
	expectedCount := int32(len(expectedIDs))

	emptyLocationMap := map[string]bool{
		comp11: true,
		comp12: true,
		comp21: true,
		comp31: false,
		comp32: false,
		comp42: true,
	}

	comps, err := s.resolver.ImageComponents(ctx, PaginatedQuery{})
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), expectedCount, int32(len(comps)))
	assert.ElementsMatch(s.T(), expectedIDs, getIDList(ctx, comps))

	for _, component := range comps {
		verifyLocationAndLayerIndex(ctx, s.T(), component, emptyLocationMap[string(component.Id(ctx))])
	}

	count, err := s.resolver.ImageComponentCount(ctx, RawQuery{})
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), expectedCount, count)
}

func (s *GraphQLImageComponentV2TestSuite) TestImageComponentsScoped() {
	ctx := SetAuthorizerOverride(s.ctx, allow.Anonymous())

	imageCompTests := []struct {
		name                 string
		id                   string
		expectedComponentIDs []string
	}{
		{
			"sha1",
			"sha1",
			[]string{
				s.componentIDMap[comp11],
				s.componentIDMap[comp21],
				s.componentIDMap[comp31],
			},
		},
		{
			"sha2",
			"sha2",
			[]string{
				s.componentIDMap[comp12],
				s.componentIDMap[comp32],
				s.componentIDMap[comp42],
			},
		},
	}

	for _, test := range imageCompTests {
		s.T().Run(test.name, func(t *testing.T) {
			image := s.getImageResolver(ctx, test.id)
			expectedCount := int32(len(test.expectedComponentIDs))

			components, err := image.ImageComponents(ctx, PaginatedQuery{})
			assert.NoError(t, err)
			assert.Equal(t, expectedCount, int32(len(components)))
			assert.ElementsMatch(t, test.expectedComponentIDs, getIDList(ctx, components))

			for _, component := range components {
				verifyLocationAndLayerIndex(ctx, s.T(), component, false)
			}

			count, err := image.ImageComponentCount(ctx, RawQuery{})
			assert.NoError(t, err)
			assert.Equal(t, expectedCount, count)
		})
	}
}

func (s *GraphQLImageComponentV2TestSuite) TestImageComponentsScopeTree() {
	ctx := SetAuthorizerOverride(s.ctx, allow.Anonymous())

	imageCompTests := []struct {
		name                      string
		id                        string
		cveToExpectedComponentIDs map[string][]string
	}{
		{
			"sha1",
			"sha1",
			map[string][]string{
				"cve-2018-1": {
					s.componentIDMap[comp11],
					s.componentIDMap[comp21],
				},
				"cve-2019-1": {
					s.componentIDMap[comp31],
				},
				"cve-2019-2": {
					s.componentIDMap[comp31],
				},
			},
		},
		{
			"sha2",
			"sha2",
			map[string][]string{
				"cve-2018-1": {
					s.componentIDMap[comp12],
				},
				"cve-2019-1": {
					s.componentIDMap[comp32],
				},
				"cve-2019-2": {
					s.componentIDMap[comp32],
				},
				"cve-2017-1": {
					s.componentIDMap[comp42],
				},
				"cve-2017-2": {
					s.componentIDMap[comp42],
				},
			},
		},
	}

	for _, test := range imageCompTests {
		s.T().Run(test.name, func(t *testing.T) {
			image := s.getImageResolver(ctx, test.id)

			vulns, err := image.ImageVulnerabilities(ctx, PaginatedQuery{})
			assert.NoError(t, err)
			for _, vuln := range vulns {
				components, err := vuln.ImageComponents(ctx, PaginatedQuery{})
				assert.NoError(t, err)
				expectedComponents := test.cveToExpectedComponentIDs[vuln.CVE(ctx)]
				require.NotNil(t, expectedComponents)

				expectedCount := int32(len(expectedComponents))
				assert.Equal(t, expectedCount, int32(len(components)))
				assert.ElementsMatch(t, expectedComponents, getIDList(ctx, components))

				for _, component := range components {
					verifyLocationAndLayerIndex(ctx, t, component, false)
				}

				count, err := vuln.ImageComponentCount(ctx, RawQuery{})
				assert.NoError(t, err)
				assert.Equal(t, expectedCount, count)
			}
		})
	}
}

func (s *GraphQLImageComponentV2TestSuite) TestImageComponentMiss() {
	ctx := SetAuthorizerOverride(s.ctx, allow.Anonymous())

	compID := graphql.ID("invalid")

	_, err := s.resolver.ImageComponent(ctx, IDQuery{ID: &compID})
	assert.Error(s.T(), err)
}

func (s *GraphQLImageComponentV2TestSuite) TestImageComponentHit() {
	ctx := SetAuthorizerOverride(s.ctx, allow.Anonymous())

	compID := graphql.ID(s.componentIDMap[comp11])

	comp, err := s.resolver.ImageComponent(ctx, IDQuery{ID: &compID})
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), compID, comp.Id(ctx))
}

func (s *GraphQLImageComponentV2TestSuite) TestImageComponentImages() {
	ctx := SetAuthorizerOverride(s.ctx, allow.Anonymous())

	imageCompTests := []struct {
		name             string
		id               string
		expectedImageIDs []string
	}{
		{
			"comp1image1",
			s.componentIDMap[comp11],
			[]string{"sha1"},
		},
		{
			"comp1image2",
			s.componentIDMap[comp12],
			[]string{"sha2"},
		},
		{
			"comp2image1",
			s.componentIDMap[comp21],
			[]string{"sha1"},
		},
		{
			"comp3image1",
			s.componentIDMap[comp31],
			[]string{"sha1"},
		},
		{
			"comp3image2",
			s.componentIDMap[comp32],
			[]string{"sha2"},
		},
		{
			"comp4image2",
			s.componentIDMap[comp42],
			[]string{"sha2"},
		},
	}

	for _, test := range imageCompTests {
		s.T().Run(test.name, func(t *testing.T) {
			comp := s.getImageComponentResolver(ctx, test.id)
			expectedCount := int32(len(test.expectedImageIDs))

			images, err := comp.Images(ctx, PaginatedQuery{})
			assert.NoError(t, err)
			assert.Equal(t, expectedCount, int32(len(images)))
			assert.ElementsMatch(t, test.expectedImageIDs, getIDList(ctx, images))

			count, err := comp.ImageCount(ctx, RawQuery{})
			assert.NoError(t, err)
			assert.Equal(t, expectedCount, count)
		})
	}
}

func (s *GraphQLImageComponentV2TestSuite) TestImageComponentImageVulnerabilities() {
	ctx := SetAuthorizerOverride(s.ctx, allow.Anonymous())

	imageCompTests := []struct {
		name            string
		id              string
		expectedCVEIDs  []string
		expectedCounter *VulnerabilityCounterResolver
	}{
		{
			"comp1os1",
			s.componentIDMap[comp11],
			[]string{
				getTestCVEID(s.T(), &storage.EmbeddedVulnerability{Cve: "cve-2018-1",
					SetFixedBy: &storage.EmbeddedVulnerability_FixedBy{
						FixedBy: "1.1",
					},
					Severity: storage.VulnerabilitySeverity_CRITICAL_VULNERABILITY_SEVERITY,
				}, s.componentIDMap[comp11]),
			},
			&VulnerabilityCounterResolver{
				all:       &VulnerabilityFixableCounterResolver{0, 1},
				critical:  &VulnerabilityFixableCounterResolver{1, 1},
				important: &VulnerabilityFixableCounterResolver{0, 0},
				moderate:  &VulnerabilityFixableCounterResolver{0, 0},
				low:       &VulnerabilityFixableCounterResolver{0, 0},
			},
		},
		{
			"comp2os1",
			s.componentIDMap[comp21],
			[]string{
				getTestCVEID(s.T(), &storage.EmbeddedVulnerability{Cve: "cve-2018-1",
					SetFixedBy: &storage.EmbeddedVulnerability_FixedBy{
						FixedBy: "1.5",
					},
					Severity: storage.VulnerabilitySeverity_CRITICAL_VULNERABILITY_SEVERITY,
				}, s.componentIDMap[comp21]),
			},
			&VulnerabilityCounterResolver{
				all:       &VulnerabilityFixableCounterResolver{0, 1},
				critical:  &VulnerabilityFixableCounterResolver{1, 1},
				important: &VulnerabilityFixableCounterResolver{0, 0},
				moderate:  &VulnerabilityFixableCounterResolver{0, 0},
				low:       &VulnerabilityFixableCounterResolver{0, 0},
			},
		},
		{
			"comp3os1",
			s.componentIDMap[comp31],
			[]string{
				getTestCVEID(s.T(), &storage.EmbeddedVulnerability{Cve: "cve-2019-1",
					Cvss:     4,
					Severity: storage.VulnerabilitySeverity_MODERATE_VULNERABILITY_SEVERITY,
				}, s.componentIDMap[comp31]),
				getTestCVEID(s.T(), &storage.EmbeddedVulnerability{Cve: "cve-2019-2",
					Cvss:     3,
					Severity: storage.VulnerabilitySeverity_LOW_VULNERABILITY_SEVERITY,
				}, s.componentIDMap[comp31]),
			},
			&VulnerabilityCounterResolver{
				all:       &VulnerabilityFixableCounterResolver{0, 0},
				critical:  &VulnerabilityFixableCounterResolver{0, 0},
				important: &VulnerabilityFixableCounterResolver{0, 0},
				moderate:  &VulnerabilityFixableCounterResolver{1, 0},
				low:       &VulnerabilityFixableCounterResolver{1, 0},
			},
		},
		{
			"comp1os2",
			s.componentIDMap[comp12],
			[]string{
				getTestCVEID(s.T(), &storage.EmbeddedVulnerability{Cve: "cve-2018-1",
					SetFixedBy: &storage.EmbeddedVulnerability_FixedBy{
						FixedBy: "1.1",
					},
					Severity: storage.VulnerabilitySeverity_CRITICAL_VULNERABILITY_SEVERITY,
				}, s.componentIDMap[comp12]),
			},
			&VulnerabilityCounterResolver{
				all:       &VulnerabilityFixableCounterResolver{0, 1},
				critical:  &VulnerabilityFixableCounterResolver{1, 1},
				important: &VulnerabilityFixableCounterResolver{0, 0},
				moderate:  &VulnerabilityFixableCounterResolver{0, 0},
				low:       &VulnerabilityFixableCounterResolver{0, 0},
			},
		},
		{
			"comp3os2",
			s.componentIDMap[comp32],
			[]string{
				getTestCVEID(s.T(), &storage.EmbeddedVulnerability{Cve: "cve-2019-1",
					Cvss:     4,
					Severity: storage.VulnerabilitySeverity_MODERATE_VULNERABILITY_SEVERITY,
				}, s.componentIDMap[comp32]),
				getTestCVEID(s.T(), &storage.EmbeddedVulnerability{Cve: "cve-2019-2",
					Cvss:     3,
					Severity: storage.VulnerabilitySeverity_LOW_VULNERABILITY_SEVERITY,
				}, s.componentIDMap[comp32]),
			},
			&VulnerabilityCounterResolver{
				all:       &VulnerabilityFixableCounterResolver{0, 0},
				critical:  &VulnerabilityFixableCounterResolver{0, 0},
				important: &VulnerabilityFixableCounterResolver{0, 0},
				moderate:  &VulnerabilityFixableCounterResolver{1, 0},
				low:       &VulnerabilityFixableCounterResolver{1, 0},
			},
		},
		{
			"comp4os2",
			s.componentIDMap[comp42],
			[]string{
				getTestCVEID(s.T(), &storage.EmbeddedVulnerability{
					Cve:      "cve-2017-1",
					Severity: storage.VulnerabilitySeverity_IMPORTANT_VULNERABILITY_SEVERITY,
				}, s.componentIDMap[comp42]),
				getTestCVEID(s.T(), &storage.EmbeddedVulnerability{
					Cve:      "cve-2017-2",
					Severity: storage.VulnerabilitySeverity_IMPORTANT_VULNERABILITY_SEVERITY,
				}, s.componentIDMap[comp42]),
			},
			&VulnerabilityCounterResolver{
				all:       &VulnerabilityFixableCounterResolver{0, 0},
				critical:  &VulnerabilityFixableCounterResolver{0, 0},
				important: &VulnerabilityFixableCounterResolver{2, 0},
				moderate:  &VulnerabilityFixableCounterResolver{0, 0},
				low:       &VulnerabilityFixableCounterResolver{0, 0},
			},
		},
	}

	for _, test := range imageCompTests {
		s.T().Run(test.name, func(t *testing.T) {
			comp := s.getImageComponentResolver(ctx, test.id)
			expectedCount := int32(len(test.expectedCVEIDs))
			test.expectedCounter.all.total = expectedCount

			vulns, err := comp.ImageVulnerabilities(ctx, PaginatedQuery{})
			assert.NoError(t, err)
			assert.Equal(t, expectedCount, int32(len(vulns)))
			assert.ElementsMatch(t, test.expectedCVEIDs, getIDList(ctx, vulns))

			count, err := comp.ImageVulnerabilityCount(ctx, RawQuery{})
			assert.NoError(t, err)
			assert.Equal(t, expectedCount, count)

			counter, err := comp.ImageVulnerabilityCounter(ctx, RawQuery{})
			assert.NoError(t, err)
			assert.Equal(t, test.expectedCounter, counter)
		})
	}
}

func (s *GraphQLImageComponentV2TestSuite) TestImageComponentDeployments() {
	ctx := SetAuthorizerOverride(s.ctx, allow.Anonymous())

	imageCompTests := []struct {
		name                 string
		id                   string
		expectedComponentIDs []string
	}{
		{
			"comp1os1",
			s.componentIDMap[comp11],
			[]string{fixtureconsts.Deployment1, fixtureconsts.Deployment2},
		},
		{
			"comp2os1",
			s.componentIDMap[comp21],
			[]string{fixtureconsts.Deployment1, fixtureconsts.Deployment2},
		},
		{
			"comp3os1",
			s.componentIDMap[comp31],
			[]string{fixtureconsts.Deployment1, fixtureconsts.Deployment2},
		},
		{
			"comp1os2",
			s.componentIDMap[comp12],
			[]string{fixtureconsts.Deployment1, fixtureconsts.Deployment3},
		},
		{
			"comp3os2",
			s.componentIDMap[comp32],
			[]string{fixtureconsts.Deployment1, fixtureconsts.Deployment3},
		},
		{
			"comp4os2",
			s.componentIDMap[comp42],
			[]string{fixtureconsts.Deployment1, fixtureconsts.Deployment3},
		},
	}

	for _, test := range imageCompTests {
		s.T().Run(test.name, func(t *testing.T) {
			comp := s.getImageComponentResolver(ctx, test.id)
			expectedCount := int32(len(test.expectedComponentIDs))

			deps, err := comp.Deployments(ctx, PaginatedQuery{})
			assert.NoError(t, err)
			assert.Equal(t, expectedCount, int32(len(deps)))
			assert.ElementsMatch(t, test.expectedComponentIDs, getIDList(ctx, deps))

			count, err := comp.DeploymentCount(ctx, RawQuery{})
			assert.NoError(t, err)
			assert.Equal(t, expectedCount, count)
		})
	}
}

func (s *GraphQLImageComponentV2TestSuite) TestTopImageVulnerability() {
	ctx := SetAuthorizerOverride(s.ctx, allow.Anonymous())

	comp := s.getImageComponentResolver(ctx, s.componentIDMap[comp31])

	expectedID := graphql.ID(getTestCVEID(s.T(), &storage.EmbeddedVulnerability{Cve: "cve-2019-1",
		Cvss:     4,
		Severity: storage.VulnerabilitySeverity_MODERATE_VULNERABILITY_SEVERITY,
	}, s.componentIDMap[comp31]))

	vuln, err := comp.TopImageVulnerability(ctx)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), expectedID, vuln.Id(ctx))
}

func (s *GraphQLImageComponentV2TestSuite) getImageResolver(ctx context.Context, id string) *imageResolver {
	imageID := graphql.ID(id)

	image, err := s.resolver.Image(ctx, struct{ ID graphql.ID }{ID: imageID})
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), imageID, image.Id(ctx))
	return image
}

func (s *GraphQLImageComponentV2TestSuite) getImageComponentResolver(ctx context.Context, id string) ImageComponentResolver {
	vulnID := graphql.ID(id)
	vuln, err := s.resolver.ImageComponent(ctx, IDQuery{ID: &vulnID})
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), vulnID, vuln.Id(ctx))
	return vuln
}

func (s *GraphQLImageComponentV2TestSuite) getComponentIDMap() map[string]string {
	return map[string]string{
		comp11: getTestComponentID(s.T(), testImages()[0].GetScan().GetComponents()[0], "sha1"),
		comp12: getTestComponentID(s.T(), testImages()[1].GetScan().GetComponents()[0], "sha2"),
		comp21: getTestComponentID(s.T(), testImages()[0].GetScan().GetComponents()[1], "sha1"),
		comp31: getTestComponentID(s.T(), testImages()[0].GetScan().GetComponents()[2], "sha1"),
		comp32: getTestComponentID(s.T(), testImages()[1].GetScan().GetComponents()[1], "sha2"),
		comp42: getTestComponentID(s.T(), testImages()[1].GetScan().GetComponents()[2], "sha2"),
	}
}
