# Agent Doctor implementation plan

Build an original Go 1.26+ CLI with standard library only and a canonical Agent Skills instruction package. Explicitly selected paths, bounded read-only collection, no action executor, no network calls during runtime. Session persistence requires --store; report exports are explicit writes.

1. Foundation: typed findings and coverage, environment discovery, safe rooted walking and streaming file access.
2. Parallel increments: filesystem junk/duplicate analyzers; OS metrics/app inventory adapters; reports/session/manual review; docs/skill/CI.
3. Integrate CLI and synthetic acceptance/safety tests. Run gofmt, go test -race, go vet and six cross builds. Independently review safety boundaries and skill dialogue.
4. Publish verified source to the requested empty GitHub repository; inspect remote revision and CI. Mark Crostini and architectures untested unless actual runtime evidence exists.

User-provided build spec is implementation input, not permission to scan user folders or run cleanup. Development workflows are copied verbatim from the user's ZIP. Requested GitHub upload authorizes source publication after verification.
