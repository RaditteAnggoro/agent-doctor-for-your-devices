# Third-party notices

The CLI uses the Go standard library and has no third-party Go module dependencies.
Go's runtime and standard library retain their own [BSD-style license](https://go.dev/LICENSE)
and associated [patent grant](https://go.dev/PATENTS). Release archives must include
these files from the toolchain used to build them as `GO-LICENSE` and `GO-PATENTS`.

Development workflow skills under `.agents/skills/` other than the product skill
were supplied by the repository owner in `codex-developer-skills.zip`; they are
preserved as project development guidance. Their inclusion does not assert
exclusive ownership of their underlying general engineering ideas.

No code from the projects listed in [INSPIRATION.md](docs/INSPIRATION.md) is bundled.
GitHub Actions are build-time services rather than runtime dependencies.
