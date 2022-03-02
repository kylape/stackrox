// Code generated by pg-bindings generator. DO NOT EDIT.

//go:build sql_integration

package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/stackrox/rox/pkg/features"
	"github.com/stackrox/rox/pkg/fixtures"
	"github.com/stackrox/rox/pkg/postgres/pgtest"
	"github.com/stackrox/rox/pkg/testutils/envisolator"
	"github.com/stretchr/testify/suite"
)

type SinglekeyStoreSuite struct {
	suite.Suite
	envIsolator *envisolator.EnvIsolator
}

func TestSinglekeyStore(t *testing.T) {
	suite.Run(t, new(SinglekeyStoreSuite))
}

func (s *SinglekeyStoreSuite) SetupTest() {
	s.envIsolator = envisolator.NewEnvIsolator(s.T())
	s.envIsolator.Setenv(features.PostgresDatastore.EnvVar(), "true")

	if !features.PostgresDatastore.Enabled() {
		s.T().Skip("Skip postgres store tests")
		s.T().SkipNow()
	}
}

func (s *SinglekeyStoreSuite) TearDownTest() {
	s.envIsolator.RestoreAll()
}

func (s *SinglekeyStoreSuite) TestStore() {
	source := pgtest.GetConnectionString(s.T())
	config, err := pgxpool.ParseConfig(source)
	if err != nil {
		panic(err)
	}
	pool, err := pgxpool.ConnectConfig(context.Background(), config)
	s.NoError(err)
	defer pool.Close()

	Destroy(pool)
	store := New(pool)

	testSingleKeyStruct := fixtures.GetTestSingleKeyStruct()
	foundTestSingleKeyStruct, exists, err := store.Get(testSingleKeyStruct.GetId())
	s.NoError(err)
	s.False(exists)
	s.Nil(foundTestSingleKeyStruct)

	s.NoError(store.Upsert(testSingleKeyStruct))
	foundTestSingleKeyStruct, exists, err = store.Get(testSingleKeyStruct.GetId())
	s.NoError(err)
	s.True(exists)
	s.Equal(testSingleKeyStruct, foundTestSingleKeyStruct)

	testSingleKeyStructCount, err := store.Count()
	s.NoError(err)
	s.Equal(testSingleKeyStructCount, 1)

	testSingleKeyStructExists, err := store.Exists(testSingleKeyStruct.GetId())
	s.NoError(err)
	s.True(testSingleKeyStructExists)
	s.NoError(store.Upsert(testSingleKeyStruct))

	foundTestSingleKeyStruct, exists, err = store.Get(testSingleKeyStruct.GetId())
	s.NoError(err)
	s.True(exists)
	s.Equal(testSingleKeyStruct, foundTestSingleKeyStruct)

	s.NoError(store.Delete(testSingleKeyStruct.GetId()))
	foundTestSingleKeyStruct, exists, err = store.Get(testSingleKeyStruct.GetId())
	s.NoError(err)
	s.False(exists)
	s.Nil(foundTestSingleKeyStruct)
}