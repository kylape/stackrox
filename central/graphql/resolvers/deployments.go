package resolvers

import (
	"context"
	"time"

	"github.com/graph-gophers/graphql-go"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/central/graphql/resolvers/loaders"
	"github.com/stackrox/rox/central/metrics"
	"github.com/stackrox/rox/central/policy/matcher"
	"github.com/stackrox/rox/central/processindicator/service"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	pkgMetrics "github.com/stackrox/rox/pkg/metrics"
	"github.com/stackrox/rox/pkg/search"
	"github.com/stackrox/rox/pkg/search/paginated"
	"github.com/stackrox/rox/pkg/search/scoped"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/utils"
)

func init() {
	schema := getBuilder()
	utils.Must(
		// NOTE: This list is and should remain alphabetically ordered
		schema.AddExtraResolvers("Deployment", []string{
			"cluster: Cluster",
			"complianceResults(query: String): [ControlResult!]!",
			"containerRestartCount: Int!",
			"containerTerminationCount: Int!",
			"deployAlertCount(query: String): Int!",
			"deployAlerts(query: String, pagination: Pagination): [Alert!]!",
			"failingPolicies(query: String, pagination: Pagination): [Policy!]!",
			"failingPolicyCount(query: String): Int!",
			"failingPolicyCounter(query: String): PolicyCounter",
			"failingRuntimePolicyCount(query: String): Int!",
			"groupedProcesses: [ProcessNameGroup!]!",
			"imageComponentCount(query: String): Int!",
			"imageComponents(query: String, pagination: Pagination): [ImageComponent!]!",
			"imageCount(query: String): Int!",
			"imageCVECountBySeverity(query: String): ResourceCountByCVESeverity!",
			"images(query: String, pagination: Pagination): [Image!]!",
			"imageVulnerabilityCount(query: String): Int!",
			"imageVulnerabilityCounter(query: String): VulnerabilityCounter!",
			"imageVulnerabilities(query: String, scopeQuery: String, pagination: Pagination): [ImageVulnerability!]!",
			"latestViolation(query: String): Time",
			"namespaceObject: Namespace",
			"plottedImageVulnerabilities(query: String): PlottedImageVulnerabilities!",
			"podCount: Int!",
			"policies(query: String, pagination: Pagination): [Policy!]!",
			"policyCount(query: String): Int!",
			"policyStatus(query: String) : String!",
			"processActivityCount: Int!",
			"secretCount(query: String): Int!",
			"secrets(query: String, pagination: Pagination): [Secret!]!",
			"serviceAccountID: String!",
			"serviceAccountObject: ServiceAccount",
			"unusedVarSink(query: String): Int",
		}),
		schema.AddQuery("deployment(id: ID): Deployment"),
		schema.AddQuery("deployments(query: String, pagination: Pagination): [Deployment!]!"),
		schema.AddQuery("deploymentCount(query: String): Int!"),
	)
}

// Deployment returns a GraphQL resolver for a given id
func (resolver *Resolver) Deployment(ctx context.Context, args struct{ *graphql.ID }) (*deploymentResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Root, "Deployment")
	if err := readDeployments(ctx); err != nil {
		return nil, err
	}
	deploymentLoader, err := loaders.GetDeploymentLoader(ctx)
	if err != nil {
		return nil, err
	}
	deployment, err := deploymentLoader.FromID(ctx, string(*args.ID))
	return resolver.wrapDeploymentWithContext(ctx, deployment, deployment != nil, err)
}

// Deployments returns GraphQL resolvers all deployments
func (resolver *Resolver) Deployments(ctx context.Context, args PaginatedQuery) ([]*deploymentResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Root, "Deployments")
	if err := readDeployments(ctx); err != nil {
		return nil, err
	}
	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return nil, err
	}
	deploymentLoader, err := loaders.GetDeploymentLoader(ctx)
	if err != nil {
		return nil, err
	}
	deployments, err := deploymentLoader.FromQuery(ctx, q)
	return resolver.wrapDeploymentsWithContext(ctx, deployments, err)
}

// DeploymentCount returns count all deployments across infrastructure
func (resolver *Resolver) DeploymentCount(ctx context.Context, args RawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Root, "DeploymentCount")
	if err := readDeployments(ctx); err != nil {
		return 0, err
	}
	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return 0, err
	}
	deploymentLoader, err := loaders.GetDeploymentLoader(ctx)
	if err != nil {
		return 0, err
	}
	return deploymentLoader.CountFromQuery(ctx, q)
}

// Cluster returns a GraphQL resolver for the cluster where this deployment runs
func (resolver *deploymentResolver) Cluster(ctx context.Context) (*clusterResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "Cluster")
	return resolver.root.Cluster(resolver.withDeploymentScopeContext(ctx), struct{ graphql.ID }{graphql.ID(resolver.data.GetClusterId())})
}

// NamespaceObject returns a GraphQL resolver for the namespace where this deployment runs
func (resolver *deploymentResolver) NamespaceObject(ctx context.Context) (*namespaceResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "NamespaceObject")
	return resolver.root.Namespace(resolver.withDeploymentScopeContext(ctx), struct{ graphql.ID }{graphql.ID(resolver.data.GetNamespaceId())})
}

// ServiceAccountObject returns a GraphQL resolver for the service account associated with this deployment
func (resolver *deploymentResolver) ServiceAccountObject(ctx context.Context) (*serviceAccountResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "ServiceAccountObject")

	if err := readServiceAccounts(ctx); err != nil {
		return nil, err
	}
	serviceAccountName := resolver.data.GetServiceAccount()
	results, err := resolver.root.ServiceAccountsDataStore.SearchRawServiceAccounts(ctx, search.NewQueryBuilder().AddExactMatches(
		search.ClusterID, resolver.data.GetClusterId()).
		AddExactMatches(search.Namespace, resolver.data.GetNamespace()).
		AddExactMatches(search.ServiceAccountName, serviceAccountName).ProtoQuery())

	if err != nil || results == nil {
		return nil, err
	}

	return resolver.root.wrapServiceAccount(results[0], true, err)
}

func (resolver *deploymentResolver) GroupedProcesses(ctx context.Context) ([]*processNameGroupResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "GroupedProcesses")

	if err := readDeploymentExtensions(ctx); err != nil {
		return nil, err
	}
	query := search.NewQueryBuilder().AddExactMatches(search.DeploymentID, resolver.data.GetId()).ProtoQuery()
	indicators, err := resolver.root.ProcessIndicatorStore.SearchRawProcessIndicators(ctx, query)
	return resolver.root.wrapProcessNameGroups(service.IndicatorsToGroupedResponses(indicators), err)
}

func (resolver *deploymentResolver) DeployAlerts(ctx context.Context, args PaginatedQuery) ([]*alertResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "DeployAlerts")

	if err := readAlerts(ctx); err != nil {
		return nil, err
	}

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return nil, err
	}

	pagination := q.GetPagination()
	q.Pagination = nil

	nested, err := search.AddAsConjunction(q, resolver.getDeploymentQuery())
	if err != nil {
		return nil, err
	}

	nested.Pagination = pagination

	nested = paginated.FillDefaultSortOption(nested, paginated.GetViolationTimeSortOption())
	return resolver.root.wrapAlerts(
		resolver.root.ViolationsDataStore.SearchRawAlerts(ctx, nested, true))
}

func (resolver *deploymentResolver) DeployAlertCount(ctx context.Context, args RawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "DeployAlertCount")

	if err := readAlerts(ctx); err != nil {
		return 0, err // could return nil, nil to prevent errors from propagating.
	}

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return 0, err
	}

	q, err = search.AddAsConjunction(resolver.getDeploymentQuery(), q)
	if err != nil {
		return 0, err
	}

	count, err := resolver.root.ViolationsDataStore.Count(ctx, q, true)
	if err != nil {
		return 0, err
	}
	return int32(count), nil
}

func (resolver *deploymentResolver) Policies(ctx context.Context, args PaginatedQuery) ([]*policyResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "Policies")

	if err := readWorkflowAdministration(ctx); err != nil {
		return nil, err
	}

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return nil, err
	}

	// remove pagination from query since we want to paginate the final result
	pagination := q.GetPagination()
	q.Pagination = &v1.QueryPagination{
		SortOptions: pagination.GetSortOptions(),
	}

	policyResolvers, err := resolver.root.wrapPolicies(resolver.getApplicablePolicies(ctx, q))
	if err != nil {
		return nil, err
	}
	for _, policyResolver := range policyResolvers {
		policyResolver.ctx = scoped.Context(ctx, scoped.Scope{
			Level: v1.SearchCategory_DEPLOYMENTS,
			IDs:   []string{resolver.data.GetId()},
		})
	}

	return paginate(pagination, policyResolvers, nil)
}

func (resolver *deploymentResolver) PolicyCount(ctx context.Context, args RawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "PolicyCount")

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return 0, err
	}

	policies, err := resolver.getApplicablePolicies(ctx, q)
	if err != nil {
		return 0, err
	}

	return int32(len(policies)), nil
}

func (resolver *deploymentResolver) getApplicablePolicies(ctx context.Context, q *v1.Query) ([]*storage.Policy, error) {
	policyLoader, err := loaders.GetPolicyLoader(ctx)
	if err != nil {
		return nil, err
	}

	policies, err := policyLoader.FromQuery(ctx, q)
	if err != nil {
		return nil, err
	}

	applicable, _ := matcher.NewDeploymentMatcher(resolver.data).FilterApplicablePolicies(policies)
	return applicable, nil
}

// FailingPolicies returns policy resolvers for policies failing on this deployment
func (resolver *deploymentResolver) FailingPolicies(ctx context.Context, args PaginatedQuery) ([]*policyResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "FailingPolicies")
	if err := readAlerts(ctx); err != nil {
		return nil, err
	}

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return nil, err
	}

	q, err = resolver.getDeploymentActiveAlertsQuery(q)
	if err != nil {
		return nil, err
	}

	// remove pagination from query since we want to paginate the final result
	pagination := q.GetPagination()
	q.Pagination = &v1.QueryPagination{SortOptions: pagination.GetSortOptions()}

	q = paginated.FillDefaultSortOption(q, paginated.GetViolationTimeSortOption())
	alerts, err := resolver.root.ViolationsDataStore.SearchRawAlerts(ctx, q, true)
	if err != nil {
		return nil, err
	}

	var policies []*storage.Policy
	set := set.NewStringSet()
	for _, alert := range alerts {
		if set.Add(alert.GetPolicy().GetId()) {
			policies = append(policies, alert.GetPolicy())
		}
	}

	policyResolvers, err := resolver.root.wrapPolicies(policies, nil)
	if err != nil {
		return nil, err
	}
	for _, policyResolver := range policyResolvers {
		policyResolver.ctx = scoped.Context(ctx, scoped.Scope{
			Level: v1.SearchCategory_DEPLOYMENTS,
			IDs:   []string{resolver.data.GetId()},
		})
	}

	return paginate(pagination, policyResolvers, nil)
}

// FailingPolicyCount returns count of policies failing on this deployment
func (resolver *deploymentResolver) FailingPolicyCount(ctx context.Context, args RawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "FailingPolicyCount")
	if err := readAlerts(ctx); err != nil {
		return 0, err
	}
	query, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return 0, err
	}
	query, err = resolver.getDeploymentActiveAlertsQuery(query)
	if err != nil {
		return 0, err
	}
	count, err := resolver.root.ViolationsDataStore.Count(ctx, query, true)
	if err != nil {
		return 0, nil
	}
	return int32(count), nil
}

// FailingRuntimePolicyCount returns count of all runtime policies failing on this deployment (not just unique)
func (resolver *deploymentResolver) FailingRuntimePolicyCount(ctx context.Context, args RawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "FailingRuntimePolicyCount")
	if err := readAlerts(ctx); err != nil {
		return 0, err
	}
	query, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return 0, err
	}
	query, err = resolver.getDeploymentActiveAlertsQuery(query)
	if err != nil {
		return 0, err
	}
	query = search.ConjunctionQuery(query,
		search.NewQueryBuilder().AddExactMatches(search.LifecycleStage, storage.LifecycleStage_RUNTIME.String()).ProtoQuery())
	count, err := resolver.root.ViolationsDataStore.Count(ctx, query, true)
	if err != nil {
		return 0, err
	}
	return int32(count), nil
}

// FailingPolicyCounter returns a policy counter for all the failed policies.
func (resolver *deploymentResolver) FailingPolicyCounter(ctx context.Context, args RawQuery) (*PolicyCounterResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "FailingPolicyCounter")
	if err := readAlerts(ctx); err != nil {
		return nil, err
	}

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return nil, err
	}

	q, err = search.AddAsConjunction(q, resolver.getDeploymentQuery())
	if err != nil {
		return nil, err
	}

	alerts, err := resolver.root.ViolationsDataStore.SearchListAlerts(ctx, q, true)
	if err != nil {
		return nil, nil
	}
	return mapListAlertsToPolicySeverityCount(alerts), nil
}

// Secrets returns the total number of secrets for this deployment
func (resolver *deploymentResolver) Secrets(ctx context.Context, args PaginatedQuery) ([]*secretResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "Secrets")

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return nil, err
	}

	pagination := q.GetPagination()
	q.Pagination = nil

	secrets, err := resolver.getDeploymentSecrets(ctx, q)
	if err != nil {
		return nil, err
	}

	return paginate(pagination, secrets, nil)
}

// SecretCount returns the total number of secrets for this deployment
func (resolver *deploymentResolver) SecretCount(ctx context.Context, args RawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "SecretCount")

	q, err := args.AsV1QueryOrEmpty()
	if err != nil {
		return 0, err
	}

	secrets, err := resolver.getDeploymentSecrets(ctx, q)
	if err != nil {
		return 0, err
	}

	return int32(len(secrets)), nil
}

func (resolver *deploymentResolver) getDeploymentSecrets(ctx context.Context, _ *v1.Query) ([]*secretResolver, error) {
	if err := readSecrets(ctx); err != nil {
		return nil, err
	}
	deployment := resolver.data
	secretSet := set.NewStringSet()
	for _, container := range deployment.GetContainers() {
		for _, secret := range container.GetSecrets() {
			secretSet.Add(secret.GetName())
		}
	}
	if secretSet.Cardinality() == 0 {
		return []*secretResolver{}, nil
	}
	psr := search.NewQueryBuilder().
		AddExactMatches(search.ClusterID, deployment.GetClusterId()).
		AddExactMatches(search.Namespace, deployment.GetNamespace()).
		AddExactMatches(search.SecretName, secretSet.AsSlice()...).
		ProtoQuery()
	secrets, err := resolver.root.SecretsDataStore.SearchRawSecrets(ctx, psr)
	if err != nil {
		return nil, err
	}
	for _, secret := range secrets {
		resolver.root.getDeploymentRelationships(ctx, secret)
	}
	return resolver.root.wrapSecrets(secrets, nil)
}

func (resolver *Resolver) getDeployment(ctx context.Context, id string) *storage.Deployment {
	deploymentLoader, err := loaders.GetDeploymentLoader(ctx)
	if err != nil {
		return nil
	}
	deployment, err := deploymentLoader.FromID(ctx, id)
	if err != nil {
		return nil
	}
	return deployment
}

func (resolver *deploymentResolver) ComplianceResults(ctx context.Context, args RawQuery) ([]*controlResultResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "ComplianceResults")
	if err := readCompliance(ctx); err != nil {
		return nil, err
	}

	runResults, err := resolver.root.ComplianceAggregator.GetResultsWithEvidence(ctx, args.String())
	if err != nil {
		return nil, err
	}
	output := newBulkControlResults()
	deploymentID := resolver.data.GetId()
	output.addDeploymentData(resolver.root, runResults, func(d *storage.ComplianceDomain_Deployment, _ *v1.ComplianceControl) bool {
		return d.GetId() == deploymentID
	})

	return *output, nil
}

func (resolver *deploymentResolver) ServiceAccountID(ctx context.Context) (string, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "ServiceAccountID")

	if err := readServiceAccounts(ctx); err != nil {
		return "", err
	}

	clusterID := resolver.ClusterId(ctx)
	serviceAccountName := resolver.ServiceAccount(ctx)

	q := search.NewQueryBuilder().
		AddExactMatches(search.ClusterID, clusterID).
		AddExactMatches(search.ServiceAccountName, serviceAccountName).
		ProtoQuery()

	results, err := resolver.root.ServiceAccountsDataStore.Search(ctx, q)
	if err != nil {
		return "", err
	}
	if len(results) == 0 {
		log.Debugf("no matching service accounts found for deployment id: %s", resolver.Id(ctx))
		return "", nil
	}
	return results[0].ID, nil
}

func (resolver *deploymentResolver) Images(ctx context.Context, args PaginatedQuery) ([]*imageResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "Images")
	if !resolver.hasImages() {
		return nil, nil
	}
	return resolver.root.Images(resolver.withDeploymentScopeContext(ctx), args)
}

func (resolver *deploymentResolver) ImageCount(ctx context.Context, args RawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "ImageCount")
	return resolver.root.ImageCount(resolver.withDeploymentScopeContext(ctx), args)
}

func (resolver *deploymentResolver) ImageComponents(ctx context.Context, args PaginatedQuery) ([]ImageComponentResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "ImageComponents")
	return resolver.root.ImageComponents(resolver.withDeploymentScopeContext(ctx), args)
}

func (resolver *deploymentResolver) ImageComponentCount(ctx context.Context, args RawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "ImageComponentCount")
	return resolver.root.ImageComponentCount(resolver.withDeploymentScopeContext(ctx), args)
}

func (resolver *deploymentResolver) ImageVulnerabilities(ctx context.Context, args PaginatedQuery) ([]ImageVulnerabilityResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "ImageVulnerabilities")
	return resolver.root.ImageVulnerabilities(resolver.withDeploymentScopeContext(ctx), args)
}

func (resolver *deploymentResolver) ImageVulnerabilityCount(ctx context.Context, args RawQuery) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "ImageVulnerabilityCount")
	return resolver.root.ImageVulnerabilityCount(resolver.withDeploymentScopeContext(ctx), args)
}

func (resolver *deploymentResolver) ImageVulnerabilityCounter(ctx context.Context, args RawQuery) (*VulnerabilityCounterResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "ImageVulnerabilityCounter")
	return resolver.root.ImageVulnerabilityCounter(resolver.withDeploymentScopeContext(ctx), args)
}

func (resolver *deploymentResolver) ImageCVECountBySeverity(ctx context.Context, q RawQuery) (*resourceCountBySeverityResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "ImageCVECountBySeverity")

	if err := readImages(ctx); err != nil {
		return nil, err
	}
	query, err := q.AsV1QueryOrEmpty()
	if err != nil {
		return nil, err
	}
	val, err := resolver.root.ImageCVEView.CountBySeverity(resolver.withDeploymentScopeContext(ctx), query)
	return resolver.root.wrapResourceCountByCVESeverityWithContext(ctx, val, err)
}

func (resolver *deploymentResolver) withDeploymentScopeContext(ctx context.Context) context.Context {
	if ctx == nil {
		err := utils.ShouldErr(errors.New("argument 'ctx' is nil"))
		if err != nil {
			log.Error(err)
		}
	}
	if resolver.ctx == nil {
		resolver.ctx = ctx
	}
	return scoped.Context(resolver.ctx, scoped.Scope{
		Level: v1.SearchCategory_DEPLOYMENTS,
		IDs:   []string{resolver.data.GetId()},
	})
}

func (resolver *deploymentResolver) PolicyStatus(ctx context.Context, args RawQuery) (string, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "PolicyStatus")

	// If we are coming from policy context, use policy context to build the query.
	var err error
	var q *v1.Query
	if scope, hasScope := scoped.GetScope(resolver.ctx); hasScope && scope.Level == v1.SearchCategory_POLICIES {
		q = search.NewQueryBuilder().AddExactMatches(search.PolicyID, scope.IDs...).ProtoQuery()
	} else {
		if q, err = args.AsV1QueryOrEmpty(); err != nil {
			return "", err
		}
	}

	alertExists, err := resolver.unresolvedAlertsExists(ctx, q)
	if err != nil {
		return "", err
	}
	if alertExists {
		return "fail", nil
	}
	return "pass", nil
}

// ProcessActivityCount returns the number of tracked processes.
func (resolver *deploymentResolver) ProcessActivityCount(ctx context.Context) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "ProcessActivityCount")

	if err := readDeploymentExtensions(ctx); err != nil {
		return 0, err
	}
	query := search.NewQueryBuilder().AddExactMatches(search.DeploymentID, resolver.data.GetId()).ProtoQuery()
	indicators, err := resolver.root.ProcessIndicatorStore.Search(ctx, query)
	if err != nil {
		return 0, err
	}
	return int32(len(indicators)), nil
}

// PodCount returns the number of pods currently active for this deployment.
func (resolver *deploymentResolver) PodCount(ctx context.Context) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "PodCount")

	query := resolver.getDeploymentRawQuery()
	return resolver.root.PodCount(ctx, RawQuery{Query: &query})
}

// ContainerRestartCount returns the number of container restarts for this deployment.
func (resolver *deploymentResolver) ContainerRestartCount(ctx context.Context) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "ContainerRestartCount")

	query := resolver.getDeploymentRawQuery()
	pods, err := resolver.root.Pods(ctx, PaginatedQuery{Query: &query})
	if err != nil {
		return 0, err
	}

	var count int
	for _, pod := range pods {
		count += len(pod.containerRestartEvents())
	}
	return int32(count), nil
}

// ContainerTerminationCount returns the number of terminated containers for this deployment.
func (resolver *deploymentResolver) ContainerTerminationCount(ctx context.Context) (int32, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "ContainerTerminationCount")

	query := resolver.getDeploymentRawQuery()
	pods, err := resolver.root.Pods(ctx, PaginatedQuery{Query: &query})
	if err != nil {
		return 0, err
	}

	var count int
	for _, pod := range pods {
		count += len(pod.containerTerminationEvents())
	}

	return int32(count), nil
}

func (resolver *deploymentResolver) hasImages() bool {
	for _, c := range resolver.data.GetContainers() {
		if c.GetImage().GetId() != "" {
			return true
		}
	}
	return false
}

func (resolver *deploymentResolver) unresolvedAlertsExists(ctx context.Context, q *v1.Query) (bool, error) {
	if err := readAlerts(ctx); err != nil {
		return false, err
	}

	q, err := resolver.getDeploymentActiveAlertsQuery(q)
	if err != nil {
		return false, err
	}
	q.Pagination = &v1.QueryPagination{Limit: 1}
	results, err := resolver.root.ViolationsDataStore.Search(ctx, q, true)
	if err != nil {
		return false, err
	}
	return len(results) > 0, nil
}

func (resolver *deploymentResolver) getDeploymentQuery() *v1.Query {
	return search.NewQueryBuilder().AddExactMatches(search.DeploymentID, resolver.data.GetId()).ProtoQuery()
}

func (resolver *deploymentResolver) getDeploymentRawQuery() string {
	return search.NewQueryBuilder().AddExactMatches(search.DeploymentID, resolver.data.GetId()).Query()
}

func (resolver *deploymentResolver) getConjunctionQuery(q *v1.Query) (*v1.Query, error) {
	return search.AddAsConjunction(q, resolver.getDeploymentQuery())
}

func (resolver *deploymentResolver) getDeploymentActiveAlertsQuery(q *v1.Query) (*v1.Query, error) {
	q, err := resolver.getConjunctionQuery(q)
	if err != nil {
		return nil, err
	}
	return search.ConjunctionQuery(q, search.NewQueryBuilder().AddExactMatches(search.ViolationState, storage.ViolationState_ACTIVE.String()).ProtoQuery()), nil
}

func (resolver *deploymentResolver) LatestViolation(ctx context.Context, args RawQuery) (*graphql.Time, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "LatestViolation")

	// If we are coming from policy context, use policy context to build the query.
	var err error
	var q *v1.Query
	if scope, hasScope := scoped.GetScope(resolver.ctx); hasScope && scope.Level == v1.SearchCategory_POLICIES {
		q = search.NewQueryBuilder().AddExactMatches(search.PolicyID, scope.IDs...).ProtoQuery()
	} else {
		if q, err = args.AsV1QueryOrEmpty(); err != nil {
			return nil, err
		}
	}

	q, err = resolver.getConjunctionQuery(q)
	if err != nil {
		return nil, err
	}

	return getLatestViolationTime(ctx, resolver.root, q)
}

// PlottedImageVulnerabilities returns the data required by top risky entity scatter-plot on vuln mgmt dashboard
func (resolver *deploymentResolver) PlottedImageVulnerabilities(ctx context.Context, args RawQuery) (*PlottedImageVulnerabilitiesResolver, error) {
	defer metrics.SetGraphQLOperationDurationTime(time.Now(), pkgMetrics.Deployments, "PlottedImageVulnerabilities")
	return resolver.root.PlottedImageVulnerabilities(resolver.withDeploymentScopeContext(ctx), args)
}

func (resolver *deploymentResolver) UnusedVarSink(_ context.Context, _ RawQuery) *int32 {
	return nil
}
