# Contributing

Start with a reproducible issue or a focused pull request. Read [AGENTS.md](AGENTS.md)
and [development guidance](docs/DEVELOPMENT.md). New dependencies need a concrete
reason and license review. Prefer the Go standard library.

Use temporary, synthetic fixtures. Never attach personal scan results or tokens.
Tests should prove observable behavior: scope rejection, excluded content never
opened, cancellation, report escaping, unknown metrics and zero target mutations.
A cross-build does not establish runtime support for that OS.

Run `go fmt ./...`, `go vet ./...`, `go test -race ./...` and
`go build ./cmd/agent-doctor` before a pull request. Explain changed behavior,
verification and remaining platform gaps. Do not weaken a test to make it pass.

Keep v1 read-only. Destructive actions, background network calls and privilege
escalation require a separate design and are outside this project's v1 scope.
Contributions to original code are provided under the repository's MIT license.
Do not copy incompatible upstream implementations.
