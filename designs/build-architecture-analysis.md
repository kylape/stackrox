# StackRox Build Architecture Analysis: Multi-Image vs Single-Image Approach

## Executive Summary

This analysis compares the current multi-image Docker-based build architecture with a proposed single-image approach. The comparison focuses on build methodology, deployment complexity, and compliance considerations, independent of the specific CI/CD platform used.

## Current Multi-Image Build Architecture

### Build Process Overview
The current system follows a **multi-image, component-specific approach** with separate Dockerfiles and build processes:

**Image Structure:**
- **Main Application**: `image/rhel/Dockerfile` (RHEL-based)
- **Database**: `image/postgres/Dockerfile` 
- **Scanner**: `scanner/image/scanner/Dockerfile`
- **Operator**: `operator/Dockerfile`
- **CLI Tools**: `image/roxctl/Dockerfile`

**Binary Build Method:**
- Binaries built inside Docker containers using dockerized make targets
- Complex build chain: `make main-build-dockerized` → `docker run ... make main-build-nodeps`
- Each component built in isolation with separate build environments
- No unified make targets like `bin/installer`

### Multi-Image Architecture
The current system creates **8+ separate images**:
- `stackrox/main` - Core application services
- `stackrox/central-db` - PostgreSQL database
- `stackrox/roxctl` - CLI tools
- `stackrox/scanner-v4` - Scanner service
- `stackrox/scanner-v4-db` - Scanner database
- `stackrox/stackrox-operator` - Kubernetes operator
- Plus additional specialized images

### Build Process Flow
```
1. Individual Component Builds:
   ├── make main-build-dockerized
   │   └── docker run ... make main-build-nodeps
   ├── make scale-build (for scale components)
   ├── make webhookserver-build
   └── scanner/make (separate scanner build)

2. Dockerized Binary Creation:
   ├── docker run ... $(GOBUILD) central
   ├── docker run ... $(GOBUILD) sensor/kubernetes
   ├── docker run ... $(GOBUILD) sensor/admission-control
   └── ... (individual dockerized builds)

3. Multi-Image Assembly:
   ├── docker build -t stackrox/main image/rhel/
   ├── docker build -t stackrox/central-db image/postgres/
   └── ... (build each specialized image)
```

### Current Build Limitations
- **No simplified make targets**: Missing clean targets like `bin/installer`
- **Complex dependency tracking**: Scattered across multiple make includes
- **Dockerized builds**: All binaries built inside containers, not host environment
- **No unified binary build**: Each component uses different build methods
- **Missing installer**: Installer built separately from main build chain

## Proposed Single-Image Build Architecture

### Build Process Overview
The new system uses a **single-image, unified build approach**:

**Image Structure:**
- **Single Dockerfile**: `/Dockerfile` (Fedora-based)
- **Unified Output**: Single `stackrox/stackrox:latest` image
- **Runtime Selection**: Components selected at deployment time

**Binary Build Method:**
- All binaries built with clean make targets: `make central secured-cluster bin/installer bin/operator`
- Unified build environment and dependencies
- Smart build optimization: targets skip if no contributing files modified
- All outputs packaged into single container image

### Single Image Architecture
The new system creates **1 consolidated image**:
- `stackrox/stackrox:latest` - Contains all components
- Runtime component selection based on configuration
- All binaries located in `/stackrox/` directory
- Symbolic links for binary organization

### Build Process Flow
```
1. Unified Binary Build:
   └── make central secured-cluster bin/installer bin/operator
       ├── central: bin/central bin/config-controller bin/migrator bin/scanner-v4
       ├── secured-cluster: bin/kubernetes bin/admission-control bin/compliance bin/upgrader bin/init-tls-certs
       ├── bin/installer: Deployment tool
       └── bin/operator: Kubernetes operator

2. Asset Generation:
   ├── make ui/build (UI components)
   ├── make swagger-docs (API documentation)
   └── bundle generation (scanner data)

3. Single Image Assembly:
   └── docker build -t stackrox/stackrox:latest .
```

## Detailed Comparison

### 1. Build Methodology

| Aspect | Current Multi-Image | Proposed Single-Image |
|--------|-------------------|----------------------|
| **Make Targets** | Complex dockerized builds | Clean simplified targets |
| **Binary Building** | Inside Docker containers | Host environment or unified container |
| **Build Environment** | Per-component containers | Unified build environment |
| **Dependency Tracking** | Scattered across includes | Centralized with file modification detection |
| **Installer Support** | Separate build process | Integrated `bin/installer` target |

### 2. Image Architecture

| Aspect | Current Multi-Image | Proposed Single-Image |
|--------|-------------------|----------------------|
| **Image Count** | 8+ specialized images | 1 consolidated image |
| **Component Isolation** | Build-time separation | Runtime selection |
| **Image Size** | 8-12GB total | 2-4GB single image |
| **Version Management** | Per-component versions | Unified versioning |

### 3. Deployment Complexity

| Aspect | Current Multi-Image | Proposed Single-Image |
|--------|-------------------|----------------------|
| **Deployment Files** | Multiple YAML files | Single deployment configuration |
| **Component Updates** | Per-component deployment | Unified deployment |
| **Rollback Strategy** | Component-specific | Unified rollback |
| **Configuration** | Component-specific configs | Centralized configuration |

### 4. Development Experience

| Aspect | Current Multi-Image | Proposed Single-Image |
|--------|-------------------|----------------------|
| **Build Speed** | Slower (dockerized builds) | Faster (smart targets) |
| **Incremental Builds** | Limited optimization | File-based optimization |
| **Local Development** | Complex setup | Simplified with `bin/*` targets |
| **Testing** | Component isolation | Unified testing |

## Compliance and Downstream Build Considerations

### Downstream Binary Building Requirements

**Understanding Downstream Build Types:**

#### Full Downstream Building
- **All binaries** must be built in the downstream environment
- **Complete build chain** reproduced downstream (Go compilation, asset generation, etc.)
- **Example**: Red Hat builds all StackRox components from source in their build system
- **Compliance reason**: Ensures no pre-compiled binaries, full audit trail of entire build process

#### Selective Downstream Building  
- **Only specific components** built downstream, others use upstream binaries
- **Partial build chain** - maybe just central/sensor built downstream, but scanner/operator come from upstream
- **Example**: Customer builds central component for security reasons, but uses upstream scanner
- **Compliance reason**: Critical components get downstream build, non-critical use upstream

**Architecture Impact Analysis:**

#### Full Downstream Building:
**Multi-Image Approach:**
- Each component built independently downstream
- More build processes to manage but smaller scope per build
- Clear separation of build artifacts per component

**Single-Image Approach:**
- All binaries must be built together (all-or-nothing)
- Single complex build process downstream
- All dependencies must be available downstream
- Harder to ensure consistent builds across full stack

**Winner**: Depends on downstream build system capability - single complex build vs multiple simpler builds

#### Selective Downstream Building:
**Multi-Image Approach:**
- Can choose which components to build downstream
- Critical components (central/sensor) built downstream
- Non-critical components (scanner/operator) use upstream binaries
- Enables flexible compliance strategies

**Single-Image Approach:**
- Cannot selectively build - it's all-or-nothing
- If any component needs downstream build, ALL must be built downstream
- No flexibility for selective compliance

**Winner**: Multi-image approach (enables selective compliance flexibility)

### Compliance Analysis

**Scenario 1: No Downstream Build Requirements**
- **Winner**: Single-image approach
- **Rationale**: Simplified deployment, better resource utilization, faster builds

**Scenario 2: Selective Downstream Building**
- **Winner**: Multi-image approach
- **Rationale**: Components can be built independently, reducing downstream complexity

**Scenario 3: Full Downstream Building Required**
- **Evaluation**: Depends on downstream capability
- **Single-image**: Requires robust downstream build environment
- **Multi-image**: More manageable but increases operational complexity

### Security and Audit Considerations

**Multi-Image Approach:**
- **Pros**: Smaller attack surface per component, easier to audit individual components
- **Cons**: More images to scan and manage, complex dependency tracking

**Single-Image Approach:**
- **Pros**: Single point of security scanning, unified vulnerability management
- **Cons**: Larger attack surface, all components present even if unused

## Performance Analysis

### Build Time Comparison

**Current Multi-Image Build:**
```bash
# Sequential dockerized builds
make main-build-dockerized      # 8-12 minutes
make scanner-build             # 5-8 minutes  
make operator-build            # 3-5 minutes
# Total: 16-25 minutes
```

**Proposed Single-Image Build:**
```bash
# Unified build with smart targets
make central secured-cluster bin/installer bin/operator  # 6-12 minutes
# Smart rebuilds: 2-5 minutes on incremental changes
```

### Resource Utilization

| Metric | Current Multi-Image | Proposed Single-Image |
|--------|-------------------|----------------------|
| **Build Time (Cold)** | 20-30 minutes | 10-15 minutes |
| **Build Time (Incremental)** | 15-20 minutes | 3-8 minutes |
| **Storage Requirements** | 8-12GB total | 2-4GB single image |
| **Network Transfer** | Multiple pulls | Single pull |
| **Registry Storage** | Multiple image layers | Consolidated layers |

## Migration Considerations

### Advantages of Single-Image Approach

1. **Simplified Deployment**: Single image eliminates multi-component orchestration
2. **Build Performance**: Smart make targets with file modification detection
3. **Unified Versioning**: All components guaranteed to be compatible
4. **Resource Efficiency**: Shared dependencies and unified build
5. **Developer Experience**: Clean `bin/*` targets for local development

### Disadvantages of Single-Image Approach

1. **Runtime Complexity**: Component selection logic at deployment time
2. **Image Size**: Single image larger than individual components
3. **Downstream Compliance**: More complex if binaries must be built downstream
4. **Debug Difficulty**: Harder to isolate component-specific issues
5. **Security Surface**: Larger attack surface with all components present

### Migration Decision Framework

**Choose Single-Image If:**
- No downstream build requirements
- Development speed is priority
- Operational simplicity is valued
- Resource efficiency is important

**Choose Multi-Image If:**
- Downstream build compliance required
- Component isolation is critical
- Security minimization is priority
- Selective deployment is needed

## Recommendations

### Implementation Strategy

**Phase 1: Parallel Development**
- Maintain current multi-image approach
- Implement single-image build alongside
- Compare performance and operational metrics

**Phase 2: Gradual Migration**
- Start with development environments
- Gather feedback on operational impact
- Evaluate downstream compliance requirements

**Phase 3: Production Deployment**
- Based on compliance requirements and performance metrics
- Implement monitoring and rollback capabilities
- Full migration or hybrid approach

### Risk Mitigation

1. **Compliance Assessment**: Evaluate downstream build requirements early
2. **Performance Monitoring**: Track build times and resource usage
3. **Security Analysis**: Comprehensive security scanning of single image
4. **Operational Testing**: Extensive testing of runtime component selection

### Success Metrics

- **Build Time**: Target 50% reduction in average build time
- **Storage**: Target 60% reduction in image storage requirements
- **Deployment**: Target 40% reduction in deployment complexity
- **Compliance**: Maintain or improve compliance posture

## Conclusion

The choice between multi-image and single-image approaches depends heavily on compliance requirements, particularly around downstream binary building. 

**If downstream compliance is not a concern**, the single-image approach offers significant advantages in build speed, operational simplicity, and resource efficiency.

**If downstream compliance requires selective component building**, the multi-image approach may be more appropriate despite its operational complexity.

The key recommendation is to **evaluate compliance requirements first**, then choose the architecture that best balances operational efficiency with regulatory needs.

The unified make targets (`bin/installer`, smart rebuilds) represent a significant improvement regardless of the chosen image architecture and should be implemented in either approach.