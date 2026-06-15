# `totp` — Starlark API Reference

The complete reference for every script-facing builtin and configuration
accessor exposed by the `totp` module. For an overview, installation, and a
quickstart, see the [README](../README.md).

The module exposes three top-level builtins via `load("totp", …)` —
`generate_code`, `validate`, and `new_secret` — plus a set of configuration
accessors (`get_<key>` / `set_<key>`) generated from the module's options. All
functions are pure computation (HMAC over a time counter): no network, no
storage, no filesystem.

## Contents

- [Functions](#functions)
  - [`generate_code`](#generate_codesecret-time0-periodcfg-digitscfg-algorithmsha1)
  - [`validate`](#validatecode-secret-time0-periodcfg-digitscfg-skew1-algorithmsha1)
  - [`new_secret`](#new_secretissuer-account_name-periodcfg-digitscfg-algorithmsha1-secret_size20)
- [Common parameters](#common-parameters)
- [Host-side time control](#host-side-time-control)
- [Configuration](#configuration)

## Functions

### `generate_code(secret, time=0, period=<cfg>, digits=<cfg>, algorithm="SHA1")`

Generates the current TOTP code for `secret`.

**Parameters:**

- `secret` (string): The base32-encoded shared secret. Must not be empty.
- `time` (int, optional): Unix timestamp (seconds) at which to evaluate the
  code. `0` (the default) means "use the module clock" — see
  [Host-side time control](#host-side-time-control).
- `period` (int, optional): TOTP period in seconds. Must be positive. Defaults
  to the `default_period` config option (`30`).
- `digits` (int, optional): Number of code digits; must be `6` or `8`. Defaults
  to the `default_digits` config option (`6`).
- `algorithm` (string, optional): HMAC hash — `"SHA1"`, `"SHA256"`, or
  `"SHA512"` (default `"SHA1"`).

**Returns:** The code as a string (`str`).

**Errors:** Raised if `secret` is empty, if `period <= 0`, if `digits` is not
`6` or `8`, if `algorithm` is unknown, or if the underlying SDK rejects the
secret.

**Example:**

```python
load("totp", "generate_code")

# Current code with module defaults
code = generate_code(secret)

# Deterministic: pin the evaluation instant
code = generate_code(secret, time=1000000000)

# 8-digit SHA256 code on a 60-second period
code = generate_code(secret, period=60, digits=8, algorithm="SHA256")
```

### `validate(code, secret, time=0, period=<cfg>, digits=<cfg>, skew=1, algorithm="SHA1")`

Validates `code` against `secret`.

**Parameters:**

- `code` (string): The code the user typed.
- `secret` (string): The base32-encoded shared secret. Must not be empty.
- `time` (int, optional): Unix timestamp (seconds) at which to evaluate. `0`
  (the default) means "use the module clock" — see
  [Host-side time control](#host-side-time-control).
- `period` (int, optional): TOTP period in seconds. Must be positive. Defaults
  to the `default_period` config option (`30`).
- `digits` (int, optional): Number of code digits; must be `6` or `8`. Defaults
  to the `default_digits` config option (`6`).
- `skew` (int, optional): How many periods of clock skew to tolerate on each
  side (default `1`, i.e. ±1 period). Must be in the range `0..1000`.
- `algorithm` (string, optional): HMAC hash — `"SHA1"`, `"SHA256"`, or
  `"SHA512"` (default `"SHA1"`).

**Returns:** `True` if the code is valid for the (skewed) window, else `False`
(`bool`).

**Errors:** Raised if `secret` is empty, if `period <= 0`, if `skew` is negative
or exceeds `1000`, if `digits` is not `6` or `8`, or if `algorithm` is unknown.

> The `skew` cap of `1000` (>8 hours at the 30s default) is far above any real
> 2FA flow; it only stops a hostile script from forcing an unbounded
> O(`skew`) HMAC loop on the host.

**Example:**

```python
load("totp", "validate")

# Validate a code the user typed (allows ±1 period of clock skew by default)
if validate(user_input, secret):
    print("authenticated")

# Deterministic round-trip in a test
ok = validate(code, secret, time=1000000000)  # => True

# Tighten the window to exactly the current period
ok = validate(user_input, secret, skew=0)
```

### `new_secret(issuer, account_name, period=<cfg>, digits=<cfg>, algorithm="SHA1", secret_size=20)`

Mints a new shared secret and its provisioning URI for an authenticator app.

**Parameters:**

- `issuer` (string): The service/issuer name shown in the authenticator. Must
  not be empty.
- `account_name` (string): The account identifier (e.g. the user's email). Must
  not be empty.
- `period` (int, optional): TOTP period in seconds. Defaults to the
  `default_period` config option (`30`).
- `digits` (int, optional): Number of code digits; must be `6` or `8`. Defaults
  to the `default_digits` config option (`6`).
- `algorithm` (string, optional): HMAC hash — `"SHA1"`, `"SHA256"`, or
  `"SHA512"` (default `"SHA1"`).
- `secret_size` (int, optional): Secret length in bytes (default `20`, the
  160-bit RFC-recommended size). Must be in the range `1..1024`.

**Returns:** A `struct` with two fields:

- `secret` (string): The base32 secret to store for the account.
- `url` (string): An `otpauth://` provisioning URI (render as a QR code for the
  user).

**Errors:** Raised if `issuer` or `account_name` is empty, if `secret_size` is
non-positive or exceeds `1024`, if `digits` is not `6` or `8`, or if `algorithm`
is unknown.

> The `secret_size` cap of `1024` bytes (8192 bits) is far above the 20-byte
> default; it only stops a hostile script from forcing an unbounded secret
> allocation on the host.

**Example:**

```python
load("totp", "new_secret", "generate_code", "validate")

# Provision a new secret for a user
key = new_secret("StarPkg", "alice@example.com")
print(key.secret)   # base32 secret to store
print(key.url)      # otpauth://totp/... (render as a QR code for the user)

# The minted secret round-trips through the other two builtins
code = generate_code(key.secret)
print(validate(code, key.secret))  # => True
```

## Common parameters

These constraints apply across the builtins above:

- `digits` must be `6` or `8`.
- `algorithm` must be `"SHA1"`, `"SHA256"`, or `"SHA512"` (an empty string is
  treated as `"SHA1"`).
- `period` must be positive.
- `skew` must be in `0..1000`; `secret_size` must be in `1..1024`. The defaults
  (`skew=1`, `secret_size=20`) are the historical values; the caps are safety
  rails that change no real script's behavior.

## Host-side time control

`totp.NewModule()` reads the wall clock. A Go host that wants deterministic or
controlled time — tests, replay, a fixed evaluation instant — constructs the
module with an injected clock:

```go
fixed := time.Unix(1000000000, 0)
module := totp.NewModuleWithClock(func() time.Time { return fixed })
```

Scripts can also pin the evaluation instant per call with the `time` keyword (a
Unix timestamp; `0` means "use the module clock"), which is the script-visible
equivalent and what the deterministic round-trip examples above rely on.

## Configuration

Each module configuration option is exposed to scripts as a pair of generated
accessor builtins (loaded from the `totp` module alongside the functions above):

- **`get_<key>()`** — returns the current value of the option.
- **`set_<key>(value)`** — sets the option (returns `None`).

An option's value resolves in priority order: an explicit `set_<key>` value, the
environment variable, then the default. These options are *defaults* only —
every per-call `period` / `digits` keyword on a builtin overrides them.

None of the `totp` options are secret, so every option exposes **both**
`get_<key>` and `set_<key>`. (A secret option would expose only its `set_<key>`
accessor — never a getter — but this module has none.)

| Option | Getter | Setter | Type | Env var | Default | Description |
|--------|--------|--------|------|---------|---------|-------------|
| `default_period` | `get_default_period` | `set_default_period` | int | `TOTP_DEFAULT_PERIOD` | `30` | Default TOTP period in seconds |
| `default_digits` | `get_default_digits` | `set_default_digits` | int | `TOTP_DEFAULT_DIGITS` | `6` | Default number of code digits (6 or 8) |

**Example:**

```python
load(
    "totp",
    "generate_code",
    # getters
    "get_default_period", "get_default_digits",
    # setters
    "set_default_period", "set_default_digits",
)

set_default_period(60)
print(get_default_period())  # 60

# generate_code now uses period=60 unless the call overrides it
code = generate_code(secret)
```
