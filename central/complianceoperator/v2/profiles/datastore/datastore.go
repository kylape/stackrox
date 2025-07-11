package datastore

import (
	"context"
	"testing"

	pgStore "github.com/stackrox/rox/central/complianceoperator/v2/profiles/store/postgres"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres"
)

// DataStore is the entry point for storing/retrieving compliance operator profiles.
//
//go:generate mockgen-wrapper
type DataStore interface {
	// GetProfile returns the profile for the given profile ID
	GetProfile(ctx context.Context, profileID string) (*storage.ComplianceOperatorProfileV2, bool, error)

	// SearchProfiles returns the profiles for the given query
	SearchProfiles(ctx context.Context, query *v1.Query) ([]*storage.ComplianceOperatorProfileV2, error)

	// UpsertProfile adds the profile to the database
	UpsertProfile(ctx context.Context, result *storage.ComplianceOperatorProfileV2) error

	// DeleteProfileForCluster removes a profile from the database
	DeleteProfileForCluster(ctx context.Context, uid string, clusterID string) error

	// DeleteProfilesByCluster deletes profiles of a specific cluster
	DeleteProfilesByCluster(ctx context.Context, clusterID string) error

	// GetProfilesByClusters gets the list of profiles for a given clusters
	GetProfilesByClusters(ctx context.Context, clusterIDs []string) ([]*storage.ComplianceOperatorProfileV2, error)

	// CountProfiles returns count of profiles matching query
	CountProfiles(ctx context.Context, q *v1.Query) (int, error)

	// GetProfilesNames gets the list of distinct profile names for the query
	GetProfilesNames(ctx context.Context, q *v1.Query, clusterIDs []string) ([]string, error)

	// CountDistinctProfiles returns count of distinct profiles matching query
	CountDistinctProfiles(ctx context.Context, q *v1.Query, clusterIDs []string) (int, error)
}

// New returns an instance of DataStore.
func New(complianceProfileStorage pgStore.Store, pool postgres.DB) DataStore {
	return &datastoreImpl{
		store: complianceProfileStorage,
		db:    pool,
	}
}

// GetTestPostgresDataStore provides a datastore connected to postgres for testing purposes.
func GetTestPostgresDataStore(_ testing.TB, pool postgres.DB) DataStore {
	store := pgStore.New(pool)
	return New(store, pool)
}
