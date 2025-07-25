// Code generated by pg-bindings generator. DO NOT EDIT.

package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stackrox/rox/central/metrics"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/logging"
	ops "github.com/stackrox/rox/pkg/metrics"
	"github.com/stackrox/rox/pkg/postgres"
	pkgSchema "github.com/stackrox/rox/pkg/postgres/schema"
	"github.com/stackrox/rox/pkg/protocompat"
	"github.com/stackrox/rox/pkg/sac/resources"
	"github.com/stackrox/rox/pkg/search"
	pgSearch "github.com/stackrox/rox/pkg/search/postgres"
	"gorm.io/gorm"
)

const (
	baseTable = "image_cves_v2"
	storeName = "ImageCVEV2"
)

var (
	log            = logging.LoggerForModule()
	schema         = pkgSchema.ImageCvesV2Schema
	targetResource = resources.Image
)

type (
	storeType = storage.ImageCVEV2
	callback  = func(obj *storeType) error
)

// Store is the interface to interact with the storage for storage.ImageCVEV2
type Store interface {
	Upsert(ctx context.Context, obj *storeType) error
	UpsertMany(ctx context.Context, objs []*storeType) error
	Delete(ctx context.Context, id string) error
	DeleteByQuery(ctx context.Context, q *v1.Query) ([]string, error)
	DeleteMany(ctx context.Context, identifiers []string) error
	PruneMany(ctx context.Context, identifiers []string) error

	Count(ctx context.Context, q *v1.Query) (int, error)
	Exists(ctx context.Context, id string) (bool, error)
	Search(ctx context.Context, q *v1.Query) ([]search.Result, error)

	Get(ctx context.Context, id string) (*storeType, bool, error)
	// Deprecated: use GetByQueryFn instead
	GetByQuery(ctx context.Context, query *v1.Query) ([]*storeType, error)
	GetByQueryFn(ctx context.Context, query *v1.Query, fn callback) error
	GetMany(ctx context.Context, identifiers []string) ([]*storeType, []int, error)
	GetIDs(ctx context.Context) ([]string, error)

	Walk(ctx context.Context, fn callback) error
	WalkByQuery(ctx context.Context, query *v1.Query, fn callback) error
}

// New returns a new Store instance using the provided sql instance.
func New(db postgres.DB) Store {
	return pgSearch.NewGloballyScopedGenericStore[storeType, *storeType](
		db,
		schema,
		pkGetter,
		insertIntoImageCvesV2,
		copyFromImageCvesV2,
		metricsSetAcquireDBConnDuration,
		metricsSetPostgresOperationDurationTime,
		targetResource,
	)
}

// region Helper functions

func pkGetter(obj *storeType) string {
	return obj.GetId()
}

func metricsSetPostgresOperationDurationTime(start time.Time, op ops.Op) {
	metrics.SetPostgresOperationDurationTime(start, op, storeName)
}

func metricsSetAcquireDBConnDuration(start time.Time, op ops.Op) {
	metrics.SetAcquireDBConnDuration(start, op, storeName)
}

func insertIntoImageCvesV2(batch *pgx.Batch, obj *storage.ImageCVEV2) error {

	serialized, marshalErr := obj.MarshalVT()
	if marshalErr != nil {
		return marshalErr
	}

	values := []interface{}{
		// parent primary keys start
		obj.GetId(),
		obj.GetImageId(),
		obj.GetCveBaseInfo().GetCve(),
		protocompat.NilOrTime(obj.GetCveBaseInfo().GetPublishedOn()),
		protocompat.NilOrTime(obj.GetCveBaseInfo().GetCreatedAt()),
		obj.GetCveBaseInfo().GetEpss().GetEpssProbability(),
		obj.GetCvss(),
		obj.GetSeverity(),
		obj.GetImpactScore(),
		obj.GetNvdcvss(),
		protocompat.NilOrTime(obj.GetFirstImageOccurrence()),
		obj.GetState(),
		obj.GetIsFixable(),
		obj.GetFixedBy(),
		obj.GetComponentId(),
		obj.GetAdvisory().GetName(),
		obj.GetAdvisory().GetLink(),
		obj.GetImageIdV2(),
		serialized,
	}

	finalStr := "INSERT INTO image_cves_v2 (Id, ImageId, CveBaseInfo_Cve, CveBaseInfo_PublishedOn, CveBaseInfo_CreatedAt, CveBaseInfo_Epss_EpssProbability, Cvss, Severity, ImpactScore, Nvdcvss, FirstImageOccurrence, State, IsFixable, FixedBy, ComponentId, Advisory_Name, Advisory_Link, ImageIdV2, serialized) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19) ON CONFLICT(Id) DO UPDATE SET Id = EXCLUDED.Id, ImageId = EXCLUDED.ImageId, CveBaseInfo_Cve = EXCLUDED.CveBaseInfo_Cve, CveBaseInfo_PublishedOn = EXCLUDED.CveBaseInfo_PublishedOn, CveBaseInfo_CreatedAt = EXCLUDED.CveBaseInfo_CreatedAt, CveBaseInfo_Epss_EpssProbability = EXCLUDED.CveBaseInfo_Epss_EpssProbability, Cvss = EXCLUDED.Cvss, Severity = EXCLUDED.Severity, ImpactScore = EXCLUDED.ImpactScore, Nvdcvss = EXCLUDED.Nvdcvss, FirstImageOccurrence = EXCLUDED.FirstImageOccurrence, State = EXCLUDED.State, IsFixable = EXCLUDED.IsFixable, FixedBy = EXCLUDED.FixedBy, ComponentId = EXCLUDED.ComponentId, Advisory_Name = EXCLUDED.Advisory_Name, Advisory_Link = EXCLUDED.Advisory_Link, ImageIdV2 = EXCLUDED.ImageIdV2, serialized = EXCLUDED.serialized"
	batch.Queue(finalStr, values...)

	return nil
}

func copyFromImageCvesV2(ctx context.Context, s pgSearch.Deleter, tx *postgres.Tx, objs ...*storage.ImageCVEV2) error {
	batchSize := pgSearch.MaxBatchSize
	if len(objs) < batchSize {
		batchSize = len(objs)
	}
	inputRows := make([][]interface{}, 0, batchSize)

	// This is a copy so first we must delete the rows and re-add them
	// Which is essentially the desired behaviour of an upsert.
	deletes := make([]string, 0, batchSize)

	copyCols := []string{
		"id",
		"imageid",
		"cvebaseinfo_cve",
		"cvebaseinfo_publishedon",
		"cvebaseinfo_createdat",
		"cvebaseinfo_epss_epssprobability",
		"cvss",
		"severity",
		"impactscore",
		"nvdcvss",
		"firstimageoccurrence",
		"state",
		"isfixable",
		"fixedby",
		"componentid",
		"advisory_name",
		"advisory_link",
		"imageidv2",
		"serialized",
	}

	for idx, obj := range objs {
		// Todo: ROX-9499 Figure out how to more cleanly template around this issue.
		log.Debugf("This is here for now because there is an issue with pods_TerminatedInstances where the obj "+
			"in the loop is not used as it only consists of the parent ID and the index.  Putting this here as a stop gap "+
			"to simply use the object.  %s", obj)

		serialized, marshalErr := obj.MarshalVT()
		if marshalErr != nil {
			return marshalErr
		}

		inputRows = append(inputRows, []interface{}{
			obj.GetId(),
			obj.GetImageId(),
			obj.GetCveBaseInfo().GetCve(),
			protocompat.NilOrTime(obj.GetCveBaseInfo().GetPublishedOn()),
			protocompat.NilOrTime(obj.GetCveBaseInfo().GetCreatedAt()),
			obj.GetCveBaseInfo().GetEpss().GetEpssProbability(),
			obj.GetCvss(),
			obj.GetSeverity(),
			obj.GetImpactScore(),
			obj.GetNvdcvss(),
			protocompat.NilOrTime(obj.GetFirstImageOccurrence()),
			obj.GetState(),
			obj.GetIsFixable(),
			obj.GetFixedBy(),
			obj.GetComponentId(),
			obj.GetAdvisory().GetName(),
			obj.GetAdvisory().GetLink(),
			obj.GetImageIdV2(),
			serialized,
		})

		// Add the ID to be deleted.
		deletes = append(deletes, obj.GetId())

		// if we hit our batch size we need to push the data
		if (idx+1)%batchSize == 0 || idx == len(objs)-1 {
			// copy does not upsert so have to delete first.  parent deletion cascades so only need to
			// delete for the top level parent

			if err := s.DeleteMany(ctx, deletes); err != nil {
				return err
			}
			// clear the inserts and vals for the next batch
			deletes = deletes[:0]

			if _, err := tx.CopyFrom(ctx, pgx.Identifier{"image_cves_v2"}, copyCols, pgx.CopyFromRows(inputRows)); err != nil {
				return err
			}
			// clear the input rows for the next batch
			inputRows = inputRows[:0]
		}
	}

	return nil
}

// endregion Helper functions

// region Used for testing

// CreateTableAndNewStore returns a new Store instance for testing.
func CreateTableAndNewStore(ctx context.Context, db postgres.DB, gormDB *gorm.DB) Store {
	pkgSchema.ApplySchemaForTable(ctx, gormDB, baseTable)
	return New(db)
}

// Destroy drops the tables associated with the target object type.
func Destroy(ctx context.Context, db postgres.DB) {
	dropTableImageCvesV2(ctx, db)
}

func dropTableImageCvesV2(ctx context.Context, db postgres.DB) {
	_, _ = db.Exec(ctx, "DROP TABLE IF EXISTS image_cves_v2 CASCADE")

}

// endregion Used for testing
