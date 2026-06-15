# 🔑 `totp` — TOTP one-time passwords for Starlark

[![Go Reference](https://pkg.go.dev/badge/github.com/starpkg/totp.svg)](https://pkg.go.dev/github.com/starpkg/totp)
[![codecov](https://codecov.io/gh/starpkg/totp/graph/badge.svg)](https://codecov.io/gh/starpkg/totp)
![binary footprint](https://img.shields.io/badge/binary_footprint-%2B0.3_MB-blue)

Generate and validate [TOTP](https://datatracker.ietf.org/doc/html/rfc6238)
(time-based one-time passwords, RFC 6238) from Starlark, built on
[pquerna/otp](https://github.com/pquerna/otp). Pure computation — no network, no
storage.

`starpkg` provides support for necessary **local** operations plus simple
abstractions over common **online** services, for ease of use. `totp` is a
**local-capability** module: it is self-contained two-factor-auth math (HMAC over
the time counter) with no I/O, so a script can mint a secret, render the
provisioning URI for an authenticator app, and verify the codes users type —
all without leaving the sandbox.

## Installation

```bash
go get github.com/starpkg/totp
```

## Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `generate_code` | `generate_code(secret, time=0, period=30, digits=6, algorithm="SHA1") -> str` | Generate the code for `secret`. `time` is a Unix timestamp; `0` means now. |
| `validate` | `validate(code, secret, time=0, period=30, digits=6, skew=1, algorithm="SHA1") -> bool` | Validate `code` against `secret`. `skew` allows ± that many periods. |
| `new_secret` | `new_secret(issuer, account_name, period=30, digits=6, algorithm="SHA1", secret_size=20) -> struct` | Mint a new secret; returns `struct(secret, url)` where `url` is an `otpauth://` provisioning URI. |

`digits` must be `6` or `8`; `algorithm` must be `SHA1`, `SHA256`, or `SHA512`.
`skew` must be in `0..1000` and `secret_size` in `1..1024` — these caps are far
above any real use (the defaults are `skew=1`, `secret_size=20`) and exist only
to keep a hostile script from forcing an unbounded validation loop or secret
allocation on the host.

## Usage

```python
load("totp", "generate_code", "validate", "new_secret")

# Provision a new secret for a user
key = new_secret("StarPkg", "alice@example.com")
print(key.secret)   # base32 secret to store
print(key.url)      # otpauth://totp/... (render as a QR code for the user)

# Generate the current code
code = generate_code(key.secret)

# Validate a code the user typed (allows ±1 period of clock skew by default)
if validate(user_input, key.secret):
    print("authenticated")
```

For deterministic results (e.g. tests), pass an explicit `time`:

```python
code = generate_code(secret, time=1000000000)
validate(code, secret, time=1000000000)   # => True
```

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `default_period` | `int` | `30` | Default TOTP period in seconds |
| `default_digits` | `int` | `6` | Default number of code digits (6 or 8) |

Settable via `TOTP_DEFAULT_PERIOD` / `TOTP_DEFAULT_DIGITS` (the env-var names are
derived from `ModuleName`). These are *defaults* only — every per-call `period` /
`digits` keyword overrides them.

### Host-side time control

`totp.NewModule()` reads the wall clock. A Go host that wants deterministic or
controlled time — tests, replay, a fixed evaluation instant — constructs the
module with an injected clock:

```go
fixed := time.Unix(1000000000, 0)
module := totp.NewModuleWithClock(func() time.Time { return fixed })
```

Scripts can also pin the evaluation instant per call with the `time` keyword (a
Unix timestamp; `0` means "use the module clock"), which is the script-visible
equivalent and what the round-trip examples above rely on.
