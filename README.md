# 🔑 `totp` — TOTP one-time passwords for Starlark

[![Go Reference](https://pkg.go.dev/badge/github.com/starpkg/totp.svg)](https://pkg.go.dev/github.com/starpkg/totp)
[![codecov](https://codecov.io/gh/starpkg/totp/graph/badge.svg)](https://codecov.io/gh/starpkg/totp)
![binary footprint](https://img.shields.io/badge/binary_footprint-%2B0.3_MB-blue)

Generate and validate [TOTP](https://datatracker.ietf.org/doc/html/rfc6238)
(time-based one-time passwords, RFC 6238) from Starlark, built on
[pquerna/otp](https://github.com/pquerna/otp). Pure computation — no network, no
storage.

## Overview

`starpkg` provides support for necessary **local** operations plus simple
abstractions over common **online** services, for ease of use. `totp` is a
**local-capability** module: it is self-contained two-factor-auth math (HMAC over
the time counter) with no I/O, so a script can mint a secret, render the
provisioning URI for an authenticator app, and verify the codes users type —
all without leaving the sandbox.

For the complete per-builtin reference — signatures, parameters, returns,
errors, examples — and the configuration accessors, see
[docs/API.md](docs/API.md).

## Installation

```bash
go get github.com/starpkg/totp
```

## Quickstart

```python
load("totp", "generate_code", "validate", "new_secret")

# Provision a new secret for a user
key = new_secret("StarPkg", "alice@example.com")
print(key.secret)   # base32 secret to store
print(key.url)      # otpauth://totp/... (render as a QR code for the user)

# Generate the current code, then validate what the user typed
# (allows ±1 period of clock skew by default)
code = generate_code(key.secret)
if validate(user_input, key.secret):
    print("authenticated")
```

For deterministic results (e.g. tests), pass an explicit `time`:

```python
code = generate_code(secret, time=1000000000)
validate(code, secret, time=1000000000)   # => True
```

## Starlark API at a glance

Top-level builtins (`load("totp", …)`):

- `generate_code(secret, time=0, period=<cfg>, digits=<cfg>, algorithm="SHA1")` — generate the current code for `secret`; returns a string.
- `validate(code, secret, time=0, period=<cfg>, digits=<cfg>, skew=1, algorithm="SHA1")` — validate `code`; `skew` allows ± that many periods; returns a bool.
- `new_secret(issuer, account_name, period=<cfg>, digits=<cfg>, algorithm="SHA1", secret_size=20)` — mint a new secret; returns `struct(secret, url)` where `url` is an `otpauth://` provisioning URI.

`digits` must be `6` or `8`; `algorithm` must be `SHA1`, `SHA256`, or `SHA512`.

See [docs/API.md](docs/API.md) for the full signatures, return values, errors,
and examples of every builtin above, plus host-side time control
(`NewModuleWithClock`).

## Configuration

The module's options (`default_period`, `default_digits`) are configured via
environment variables (`TOTP_*`) or per-option `get_<key>` / `set_<key>` accessor
builtins, and serve as *defaults* that each per-call `period` / `digits` keyword
overrides. See the
[Configuration section of docs/API.md](docs/API.md#configuration) for the full
option table, defaults, and accessors.

## License

MIT
