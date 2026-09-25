# Agent guidance

## Safety and validation

- Keep local validation unprivileged and independent of live firewall state. Use `make test`, `make check`, and `make package` for safe local checks.
- Run nftables integration tests and packet-load performance tests only in disposable GitHub-hosted CI. Integration uses `scripts/ci/isolate.sh`; performance runs bfw and k6 in separate containers on an internal-only Docker network with no published ports. Do not execute integration-tagged tests or `scripts/perf/run.sh` on a workstation.
- Read `README.md`'s privileged-testing and performance sections when changing those paths. Treat `.github/workflows/ci.yml` and `Makefile` as the source of truth for CI jobs and local targets.

## Design and implementation

- Apply **YAGNI**: implement the requested behavior and its acceptance criteria, without speculative options, retries, or abstraction.
- Apply **KISS**: prefer explicit control flow and existing project patterns over new layers or dependencies.
- Apply **DRY** when logic shares a stable invariant; avoid both copied behavior that can drift and abstractions created only to remove a few repeated lines.
- Preserve the documented ufw-compatible CLI, output, and exit-code behavior unless the task explicitly changes that contract. Update implementation, tests, and relevant user documentation together.
- Keep errors actionable, state changes atomic where the existing design requires it, and cleanup correct on failure paths.

## Comments

- Comment public Go APIs with their contract. Explain non-obvious rationale, invariants, ordering constraints, security boundaries, and compatibility requirements where a maintainer would otherwise have to rediscover them.
- For complex control flow, document preconditions, state transitions, and failure behavior. Keep comments complete enough to preserve the relevant reasoning, but do not narrate obvious statements or duplicate what the code already expresses.
- Change comments with the behavior they describe; remove comments that become stale. Use TODOs only when the task explicitly requires deferred work and names its owner or condition.

## Tests and completion

- Add deterministic tests for consumer-visible behavior, boundaries, state transitions, and failure paths. Prefer temporary directories and injected fakes; avoid tests that only echo wiring or pin incidental output.
- Keep unit tests unprivileged. Integration tests use the `integration` build tag and run only in the isolated CI job; local compilation is safe, local execution is not.
- Run the focused safe check for each changed path, then the relevant broader checks. State clearly when a privileged or hosted-only path was not exercised.

## Commits

- Use Conventional Commits: `type(scope): summary`, with an optional scope and a concise imperative summary.
- Use standard types such as `feat`, `fix`, `test`, `docs`, `refactor`, `perf`, `ci`, and `chore`. Keep each commit focused on one coherent change.
