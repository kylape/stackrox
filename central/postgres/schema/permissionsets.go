// Code generated by pg-bindings generator. DO NOT EDIT.

package schema

import (
	"reflect"

	"github.com/stackrox/rox/central/globaldb"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/walker"
)

var (
	// CreateTablePermissionsetsStmt holds the create statement for table `permissionsets`.
	CreateTablePermissionsetsStmt = &postgres.CreateStmts{
		Table: `
               create table if not exists permissionsets (
                   Id varchar,
                   serialized bytea,
                   PRIMARY KEY(Id)
               )
               `,
		Indexes:  []string{},
		Children: []*postgres.CreateStmts{},
	}

	// PermissionsetsSchema is the go schema for table `permissionsets`.
	PermissionsetsSchema = func() *walker.Schema {
		schema := globaldb.GetSchemaForTable("permissionsets")
		if schema != nil {
			return schema
		}
		schema = walker.Walk(reflect.TypeOf((*storage.PermissionSet)(nil)), "permissionsets")
		globaldb.RegisterTable(schema)
		return schema
	}()
)