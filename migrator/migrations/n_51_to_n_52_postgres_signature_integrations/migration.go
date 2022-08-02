// Code generated by pg-bindings generator. DO NOT EDIT.
package n51ton52

import (
	"context"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/migrator/migrations"
	"github.com/stackrox/rox/migrator/migrations/loghelper"
	legacy "github.com/stackrox/rox/migrator/migrations/n_51_to_n_52_postgres_signature_integrations/legacy"
	pgStore "github.com/stackrox/rox/migrator/migrations/n_51_to_n_52_postgres_signature_integrations/postgres"
	"github.com/stackrox/rox/migrator/types"
	pkgMigrations "github.com/stackrox/rox/pkg/migrations"
	pkgSchema "github.com/stackrox/rox/pkg/postgres/schema"
	"github.com/stackrox/rox/pkg/sac"
	"gorm.io/gorm"
)

var (
	migration = types.Migration{
		StartingSeqNum: pkgMigrations.CurrentDBVersionSeqNumWithoutPostgres() + 51,
		VersionAfter:   storage.Version{SeqNum: int32(pkgMigrations.CurrentDBVersionSeqNumWithoutPostgres()) + 52},
		Run: func(databases *types.Databases) error {
			legacyStore, err := legacy.New(databases.PkgRocksDB)
			if err != nil {
				return err
			}
			if err := move(databases.GormDB, databases.PostgresDB, legacyStore); err != nil {
				return errors.Wrap(err,
					"moving signature_integrations from rocksdb to postgres")
			}
			return nil
		},
	}
	batchSize = 10000
	schema    = pkgSchema.SignatureIntegrationsSchema
	log       = loghelper.LogWrapper{}
)

func move(gormDB *gorm.DB, postgresDB *pgxpool.Pool, legacyStore legacy.Store) error {
	ctx := sac.WithAllAccess(context.Background())
	store := pgStore.New(postgresDB)
	pkgSchema.ApplySchemaForTable(context.Background(), gormDB, schema.Table)
	var signatureIntegrations []*storage.SignatureIntegration
	err := walk(ctx, legacyStore, func(obj *storage.SignatureIntegration) error {
		signatureIntegrations = append(signatureIntegrations, obj)
		if len(signatureIntegrations) == batchSize {
			if err := store.UpsertMany(ctx, signatureIntegrations); err != nil {
				log.WriteToStderrf("failed to persist signature_integrations to store %v", err)
				return err
			}
			signatureIntegrations = signatureIntegrations[:0]
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(signatureIntegrations) > 0 {
		if err = store.UpsertMany(ctx, signatureIntegrations); err != nil {
			log.WriteToStderrf("failed to persist signature_integrations to store %v", err)
			return err
		}
	}
	return nil
}

func walk(ctx context.Context, s legacy.Store, fn func(obj *storage.SignatureIntegration) error) error {
	return s.Walk(ctx, fn)
}

func init() {
	migrations.MustRegisterMigration(migration)
}