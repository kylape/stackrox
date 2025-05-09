package datastore

import (
	"context"
	"testing"
	"time"

	processIndicatorStore "github.com/stackrox/rox/central/processindicator/datastore"
	"github.com/stackrox/rox/central/processlisteningonport/store"
	plopStore "github.com/stackrox/rox/central/processlisteningonport/store/postgres"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres"
)

// WalkFn is a convenient type alias to use for the Walk function
type WalkFn = func(plop *storage.ProcessListeningOnPortStorage) error

// DataStore interface for ProcessListeningOnPort object interaction with the database
//
//go:generate mockgen-wrapper
type DataStore interface {
	AddProcessListeningOnPort(
		ctx context.Context,
		clusterID string,
		portProcesses ...*storage.ProcessListeningOnPortFromSensor,
	) error
	GetProcessListeningOnPort(
		ctx context.Context,
		deployment string,
	) ([]*storage.ProcessListeningOnPort, error)
	WalkAll(ctx context.Context, fn WalkFn) error
	RemoveProcessListeningOnPort(ctx context.Context, ids []string) error
	RemovePlopsByPod(ctx context.Context, id string) error
	PruneOrphanedPLOPs(ctx context.Context, orphanWindow time.Duration) int64
	PruneOrphanedPLOPsByProcessIndicators(ctx context.Context, orphanWindow time.Duration)
	RemovePLOPsWithoutProcessIndicatorOrProcessInfo(ctx context.Context) (int64, error)
	RemovePLOPsWithoutPodUID(ctx context.Context) (int64, error)
}

// New creates a data store object to access the database. Since some
// operations require join with ProcessIndicator table, both PLOP store and
// ProcessIndicator datastore are needed.
func New(
	plopStorage store.Store,
	indicatorDataStore processIndicatorStore.DataStore,
	pool postgres.DB,
) DataStore {
	ds := newDatastoreImpl(plopStorage, indicatorDataStore, pool)
	return ds
}

// GetTestPostgresDataStore provides a datastore connected to postgres for testing purposes.
func GetTestPostgresDataStore(t testing.TB, pool postgres.DB) DataStore {
	plopDBstore := plopStore.NewFullStore(pool)
	indicatorDS := processIndicatorStore.GetTestPostgresDataStore(t, pool)
	return newDatastoreImpl(plopDBstore, indicatorDS, pool)
}
