# Database Schema Migration: Moving Away from Generated Schemas

## Background

StackRox Central currently generates database schemas from protobuf definitions using the `walker` and `pg-table-bindings` packages. This approach was initially adopted to accelerate PostgreSQL migration but has become a significant development bottleneck.

## Current State Analysis

### Schema Generation System

The current system consists of:
- **Walker Package** (`pkg/postgres/walker/`): Reflects on protobuf structs to extract schema metadata
- **PG Table Bindings Generator** (`tools/generate-helpers/pg-table-bindings/`): Code generation tool that creates GORM models and schema definitions
- **Dual Storage Pattern**: Every entity stores both extracted searchable fields and complete protobuf as bytea

### Storage Pattern Example
```sql
CREATE TABLE deployments (
    id UUID PRIMARY KEY,
    name VARCHAR NOT NULL,           -- Extracted for search
    namespace_id UUID,               -- Extracted for search
    -- ... other extracted fields
    serialized BYTEA NOT NULL        -- Complete protobuf object
);
```

### Performance Bottlenecks Identified

1. **Query Performance Issues**
   - Evidence of 30-second slow query thresholds (`ROX_SLOW_QUERY_THRESHOLD`)
   - Full table scans due to complex queries (documented in `central/pruning/pruning.go:875-877`)
   - Manual query restructuring required to use indexes

2. **Storage Overhead**
   - Dual storage of data (extracted fields + bytea serialization)
   - Extensive database size monitoring infrastructure
   - Storage efficiency concerns requiring active pruning

3. **Search Limitations**
   - Bytea fields prevent indexing of nested protobuf data
   - Manual extraction required for every searchable field
   - Limited ad-hoc query capabilities

4. **Development Constraints**
   - Generator limitations require extension before new features
   - Complex migration process for schema changes
   - Interconnected components multiply development work

## Migration Strategy

### Phase 1: JSON Migration (Immediate Impact)

**Objective**: Replace bytea storage with JSONB to enable queryability while maintaining existing search infrastructure.

**Implementation**:
```sql
-- Replace bytea with JSONB
ALTER TABLE deployments 
DROP COLUMN serialized,
ADD COLUMN data JSONB NOT NULL;

-- Enable efficient querying
CREATE INDEX idx_deployments_data_gin ON deployments USING gin(data);
CREATE INDEX idx_deployments_containers ON deployments USING gin((data->'containers'));
```

**Benefits**:
- Eliminates bytea performance issues
- Enables PostgreSQL JSON operators for complex queries
- Maintains existing search columns during transition
- Debuggable JSON vs opaque bytea

**Query Examples**:
```sql
-- Find deployments with specific container image
SELECT * FROM deployments 
WHERE data->'containers' @> '[{"config": {"image": {"name": {"registry": "docker.io"}}}}]';

-- Complex nested queries
SELECT * FROM deployments 
WHERE data->'annotations' ? 'security.stackrox.io/policy'
AND data->'spec'->'replicas' > 1;
```

### Phase 2: Selective Normalization (Medium Risk)

**Objective**: Normalize high-value, frequently-queried entities while keeping complex nested structures in JSON.

**Target Entities** (in order of complexity):
1. **Images** - Moderate complexity, high query volume
2. **Alerts** - Frequent queries, manageable structure  
3. **Policies** - Complex but queryable
4. **Nodes** - Moderate complexity

**Example Hybrid Schema**:
```sql
CREATE TABLE images (
    -- Normalized fields for critical queries
    id UUID PRIMARY KEY,
    name_registry VARCHAR NOT NULL,
    name_remote VARCHAR NOT NULL,
    name_tag VARCHAR,
    scan_time TIMESTAMP,
    
    -- JSON for complex nested data
    scan_results JSONB,
    metadata JSONB,
    
    -- Indexes for both approaches
    INDEX idx_images_name_components (name_registry, name_remote, name_tag),
    INDEX idx_images_scan_results_gin USING gin(scan_results)
);
```

### Phase 3: Full Normalization (High Risk)

**Objective**: Tackle the most complex entities like `Deployment` with full relational normalization.

**Only proceed if**:
- JSON performance proves insufficient for specific use cases
- Complex queries require full relational capabilities
- Team has bandwidth for extensive testing

### Phase 4: Eliminate Schema Generation

**Objective**: Remove the `walker` and `pg-table-bindings` packages entirely.

**Implementation**:
- Hand-craft remaining schemas
- Remove code generation infrastructure
- Establish standard schema evolution processes

## Migration Implementation Plan

### Phase 1 Rollout

1. **Preparation**
   - Create migration utilities for protobuf → JSON conversion
   - Establish JSON indexing patterns
   - Update query interfaces to support JSON operations

2. **Entity-by-Entity Migration**
   - Start with low-risk entities (e.g., `ConfigurationHealth`)
   - Progress to medium-risk entities (e.g., `IntegrationHealth`)
   - Monitor performance and adjust indexing

3. **Testing & Validation**
   - Performance testing with real data volumes
   - Query pattern validation
   - Rollback procedures

### Success Metrics

- **Query Performance**: Eliminate 30+ second queries
- **Storage Efficiency**: Reduce dual storage overhead
- **Development Velocity**: Faster schema evolution
- **Operational Simplicity**: Standard SQL debugging vs bytea inspection

### Risks & Mitigations

1. **Performance Regression**
   - **Risk**: JSON queries slower than current extracted fields
   - **Mitigation**: Comprehensive performance testing, selective normalization fallback

2. **Migration Complexity**
   - **Risk**: Data corruption during bytea → JSON conversion
   - **Mitigation**: Thorough testing, gradual rollout, rollback procedures

3. **Query Compatibility**
   - **Risk**: Existing queries break with new schema
   - **Mitigation**: Compatibility layer, incremental migration

## Future Architecture

### Target State
- **Hybrid Storage**: Critical fields normalized, complex data in JSON
- **Standard Schema Evolution**: Traditional database migration patterns
- **Full Query Capability**: Both relational and JSON operations available
- **Operational Simplicity**: Standard PostgreSQL troubleshooting

### Long-term Benefits
- **Developer Experience**: Faster iteration, no generator limitations
- **Performance**: Optimized queries, efficient storage
- **Maintenance**: Standard SQL operations, better debugging
- **Scalability**: Database-native optimizations available

## Conclusion

The migration away from generated schemas represents a significant architectural improvement that will:
- Immediately improve query performance through JSON storage
- Reduce development friction by eliminating generator limitations
- Enable standard database optimization techniques
- Provide a path to full relational normalization where beneficial

The phased approach minimizes risk while delivering incremental value, with JSON migration providing immediate benefits and selective normalization enabling long-term optimization.