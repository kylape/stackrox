# StackRox Tekton Pipeline Backlog

## High Priority
- **Multi-arch builds** - Add support for amd64/arm64 architectures
- **Fix npm caching bug** - Resolve current npm cache issues  
- **E2E testing tasks** - Create end-to-end testing pipeline tasks

## Medium Priority
- **Combine cache buckets** - Use subfolders instead of separate buckets
- **Build collector** - Add collector component to pipeline
- **Add linting tasks** - Include code quality checks (golangci-lint, ui-lint, etc.)
- **Add image layer caching** - Cache container build layers
- **Add go binary caching** - Cache compiled binaries
- **Add DB image pipelines** - Create separate pipelines for central-db, scanner-db, scanner-v4-db images

## Low Priority
- **Release builds** - Production builds without dev/debug packages, trim binaries

---
*Generated: 2025-06-28*