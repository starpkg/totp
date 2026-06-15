# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`starpkg/totp` is an **L4 domain module** of the Star\* ecosystem: it exposes
[TOTP](https://datatracker.ietf.org/doc/html/rfc6238) (time-based one-time
passwords, RFC 6238) to Starlark scripts. A script imports the module, mints a
secret + provisioning URI, generates the current code, and validates codes a
user types.

`starpkg`'s charter is **support for necessary local operations + simple
abstractions over common online services, for ease of use.** `totp` sits firmly
on the **local-capability** side: it is pure two-factor-auth computation (HMAC
over a time counter) built on `github.com/pquerna/otp` — **no network, no
storage, no filesystem.** The only ambient input is the wall clock, which the
host can override (see Host-side time control). That makes it the simplest kind
of starpkg module: a deterministic function library with a small config surface.

Layer position: depends downward on `starpkg/base` (the module/config system),
`1set/starlet` (the Machine + `ModuleLoader`), and transitively `1set/starlight`
+ `go.starlark.net`. Nothing in the ecosystem depends on it.

## Dev commands

Pure Go library with a Makefile. From this repo:

```bash
make test                                  # -race -cover, the working bar
make ci                                    # -race -cover profile + bench compile (what CI runs)
go test ./... -run TestGenerateValidateRoundTrip   # a single test
gofmt -l . && go vet ./...                 # must be clean before commit
```

**Verify on the go floor in Docker** — this repo's floor is **go 1.19** (its
`go.mod`), and the pinned `go.starlark.net` baseline uses `maphash.String` (needs
≥1.19), so behavior on the floor must be checked in a container rather than the
newer local toolchain:

```bash
docker run --rm -v "$PWD":/src -v "$HOME/go/pkg/mod":/go/pkg/mod -w /src golang:1.19 go test -race -count=1 ./...
```

Integration scripts under `../test/totp/*.star` live in the **private
`starpkg/test` repo** and auto-skip when that directory is absent (e.g. in CI and
on a fresh clone); this module's unit tests are entirely self-contained.

## Architecture (the part that spans files)

The module is a thin, single-file bridge — there is no per-feature file fan-out
because the surface is three pure functions over one third-party SDK.

- **`totp.go`** — the entire module. It holds:
  - `Module` — wraps a `base.ConfigurableModule` (+ its `ConfigurableModuleExt`
    for typed config reads) and a `clock func() time.Time`. `NewModule()` uses
    `time.Now`; `NewModuleWithClock(clock)` injects one.
  - Config: two options registered via
    `base.NewConfigurableModuleWithConfigOptions` —
    `default_period` (30) and `default_digits` (6) — each given a name,
    description, and an env var derived from `ModuleName` (`TOTP_DEFAULT_PERIOD`,
    `TOTP_DEFAULT_DIGITS`) by `genConfigOption`.
  - `LoadModule()` — registers the three script-facing builtins:
    **`generate_code`**, **`validate`**, **`new_secret`**.
  - The three handler methods (`generateCode`, `validate`, `newSecret`) — each
    unpacks args, validates options, and delegates to the SDK.
  - Helpers: `resolveDigits` (6→`DigitsSix`, 8→`DigitsEight`, else error),
    `resolveAlgorithm` (`""`/`SHA1`/`SHA256`/`SHA512` → `otp.Algorithm`, else
    error), and `at(ts)` (the time resolver: `ts>0` → `time.Unix(ts,0)`, else the
    module clock).

**Third-party SDK wrap points** — all in `totp.go`, all from `pquerna/otp`:
`totp.GenerateCodeCustom` (backs `generate_code`), `totp.ValidateCustom` (backs
`validate`), `totp.Generate` (backs `new_secret`, returning a key whose
`.Secret()` and `.URL()` become the `secret`/`url` struct fields).

**Data flow** — script keyword args → `starlark.UnpackArgs` → option validation
(empty secret, non-positive period, negative skew, digits/algorithm resolution) →
`m.at(ts)` resolves the evaluation instant → SDK call → result marshalled back
(`starlark.String` / `starlark.Bool` / a `starlarkstruct.Struct`).

## Invariants / hardening (preserve when editing)

This is pure computation, so the hardening surface is small but real:

1. **No host panics from script input.** Every builtin returns a Starlark error
   for bad input rather than panicking: empty `secret`, `period <= 0`, negative
   `skew`, `digits` not in {6,8}, unknown `algorithm`, and empty
   `issuer`/`account_name` are all checked before the SDK is called. Errors are
   wrapped with the builtin name (`b.Name()`). New options must keep this
   validate-before-call shape.
2. **Deterministic, injectable time.** All time resolution funnels through
   `m.at(ts)` so there is exactly one clock source — the per-call `time` keyword
   or the module's `clock`. Don't call `time.Now()` directly inside a handler;
   route through `at`.
3. **Backward compatibility (iron rule).** `NewModule()` == wall-clock,
   `default_period`=30, `default_digits`=6, `skew`=1, `algorithm`="SHA1",
   `secret_size`=20 — the historical defaults. Any new option must default to
   today's observable behavior so existing scripts run identically. The
   per-call `period`/`digits` keywords override the config defaults, never the
   reverse.

## Test organization

Group by functional goal — **do not add one `*_test.go` per fix.** `totp_test.go`
is the home, opened with a commented section list:
`TestGenerateValidateRoundTrip` (generate/validate round-trip + stale-window
rejection), `TestEightDigits`, `TestNewSecret`, and `TestOptionErrors` (a
table of option-validation errors). Add a new test as a **section here**, not a
new file. Tests drive real Starlark through `starlet.NewDefault()` (the `run`
helper); no third-party test framework. When the private `../test/totp/*.star`
integration scripts are wired, they belong in a single harness section, not a
new file.

## Documentation

Three layers must stay in sync (enforced by the doc standard,
`plan/starpkg文档标准（DOC-STD）`):
- **`README.md`** — every script-facing builtin documented as a backtick
  whole-word with its correct signature/args/return; host levers
  (`NewModuleWithClock`, the env vars) documented too. The doc-coverage gate
  (`doccov`) fails CI if a registered builtin is missing from the README.
- **GoDoc** — package comment + a doc comment on every exported symbol
  (`ModuleName`, `Module`, `NewModule`, `NewModuleWithClock`, `LoadModule`),
  first word = the symbol name (gated by `revive`'s `exported` rule in CI).
- **`CLAUDE.md`** — this file.

## Release discipline

- **Floor = go 1.19** (this repo's `go.mod`); a repo's floor only rises in its
  own isolated pin-upgrade PR.
- **CI matrix** = `[1.19.x, 1.25.x]` via the centralized reusable workflow in
  `1set/meta` (`go-ci.yml`, pinned to a commit SHA; `doc-coverage: true` adds the
  README gate).
- **Pin upgrade is the last PR of the series** — `go.starlark.net` + `1set/*`
  deps + go floor move together in one isolated PR, after all fixes; never tag
  before it merges.
- **Bumping the version, the go floor, or tagging are user-confirmed actions** —
  never tag autonomously; draft title + notes and get explicit approval; default
  to patch bumps; published tags are immutable.
