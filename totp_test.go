package totp

// Tests for the totp module.
//
// Sections:
//   - generate/validate round-trip at a fixed time
//   - new_secret
//   - option validation errors (bad digits/algorithm, empty secret, non-positive period)
//   - algorithm coverage (SHA256/SHA512 round-trips, default == SHA1)
//   - injected clock (NewModuleWithClock + script time=0 / negative ts)
//   - config defaulting + per-call override (backward-compat iron rule, env vars)
//   - hardening: bounded skew / secret_size, invalid-secret error, no host panic

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/1set/starlet"
)

func run(t *testing.T, script string) (map[string]interface{}, error) {
	t.Helper()
	m := starlet.NewDefault()
	m.SetScriptContent([]byte(script))
	m.SetLazyloadModules(map[string]starlet.ModuleLoader{ModuleName: NewModule().LoadModule()})
	return m.Run()
}

// runWithModule drives a script against a caller-supplied Module, so tests can
// inject a clock or pre-set config defaults.
func runWithModule(t *testing.T, mod *Module, script string) (map[string]interface{}, error) {
	t.Helper()
	m := starlet.NewDefault()
	m.SetScriptContent([]byte(script))
	m.SetLazyloadModules(map[string]starlet.ModuleLoader{ModuleName: mod.LoadModule()})
	return m.Run()
}

// --- generate/validate round-trip --------------------------------------------

func TestGenerateValidateRoundTrip(t *testing.T) {
	script := `
load("totp", "generate_code", "validate")
secret = "JBSWY3DPEHPK3PXP"
code = generate_code(secret, time=1000000000)
ok = validate(code, secret, time=1000000000)
# A code from a window far away must not validate (default skew=1).
stale = validate(code, secret, time=1000100000)
digits = len(code)
`
	res, err := run(t, script)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res["digits"] != int64(6) {
		t.Errorf("code length = %v, want 6", res["digits"])
	}
	if res["ok"] != true {
		t.Errorf("validate of fresh code = %v, want true", res["ok"])
	}
	if res["stale"] != false {
		t.Errorf("validate of stale code = %v, want false", res["stale"])
	}
}

func TestEightDigits(t *testing.T) {
	res, err := run(t, `
load("totp", "generate_code", "validate")
secret = "JBSWY3DPEHPK3PXP"
code = generate_code(secret, time=1000000000, digits=8)
n = len(code)
ok = validate(code, secret, time=1000000000, digits=8)
`)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res["n"] != int64(8) {
		t.Errorf("code length = %v, want 8", res["n"])
	}
	if res["ok"] != true {
		t.Errorf("8-digit validate = %v, want true", res["ok"])
	}
}

// --- new_secret --------------------------------------------------------------

func TestNewSecret(t *testing.T) {
	res, err := run(t, `
load("totp", "new_secret", "generate_code", "validate")
k = new_secret("StarPkg", "alice@example.com")
secret = k.secret
url = k.url
# The freshly minted secret round-trips.
code = generate_code(secret, time=1000000000)
ok = validate(code, secret, time=1000000000)
`)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if s, _ := res["secret"].(string); s == "" {
		t.Error("secret is empty")
	}
	if u, _ := res["url"].(string); !strings.HasPrefix(u, "otpauth://totp/") {
		t.Errorf("url = %q, want otpauth://totp/ prefix", res["url"])
	}
	if res["ok"] != true {
		t.Errorf("minted-secret round-trip = %v, want true", res["ok"])
	}
}

// --- option validation errors ------------------------------------------------

func TestOptionErrors(t *testing.T) {
	const sec = "JBSWY3DPEHPK3PXP"
	// Each case must produce a Starlark error (never a host panic) and the
	// error text must name the offending option, so a script author can tell
	// what they got wrong. want is a substring asserted on err.Error().
	cases := []struct {
		name, script, want string
	}{
		{"generate bad digits", `load("totp","generate_code"); generate_code("` + sec + `", digits=7)`, "digits must be 6 or 8"},
		{"generate bad algorithm", `load("totp","generate_code"); generate_code("` + sec + `", algorithm="MD5")`, "algorithm must be SHA1, SHA256, or SHA512"},
		{"generate empty secret", `load("totp","generate_code"); generate_code("")`, "secret must not be empty"},
		{"generate zero period", `load("totp","generate_code"); generate_code("` + sec + `", period=0)`, "period must be positive"},
		{"generate negative period", `load("totp","generate_code"); generate_code("` + sec + `", period=-5)`, "period must be positive"},
		{"generate missing secret arg", `load("totp","generate_code"); generate_code()`, "missing argument"},
		{"generate bad arg type", `load("totp","generate_code"); generate_code("` + sec + `", period="thirty")`, `for parameter "period"`},
		{"validate bad arg type", `load("totp","validate"); validate("123456", "` + sec + `", skew="one")`, `for parameter "skew"`},
		{"new_secret bad arg type", `load("totp","new_secret"); new_secret("Acme", "a@b.com", secret_size="big")`, `for parameter "secret_size"`},
		{"validate empty secret", `load("totp","validate"); validate("123456", "")`, "secret must not be empty"},
		{"validate zero period", `load("totp","validate"); validate("123456", "` + sec + `", period=0)`, "period must be positive"},
		{"validate negative skew", `load("totp","validate"); validate("123456", "` + sec + `", skew=-1)`, "skew must not be negative"},
		{"validate bad digits", `load("totp","validate"); validate("123456", "` + sec + `", digits=5)`, "digits must be 6 or 8"},
		{"validate bad algorithm", `load("totp","validate"); validate("123456", "` + sec + `", algorithm="sha-1")`, "algorithm must be SHA1"},
		{"new_secret empty issuer", `load("totp","new_secret"); new_secret("", "a@b.com")`, "issuer and account_name are required"},
		{"new_secret empty account", `load("totp","new_secret"); new_secret("Acme", "")`, "issuer and account_name are required"},
		{"new_secret zero secret_size", `load("totp","new_secret"); new_secret("Acme", "a@b.com", secret_size=0)`, "secret_size must be positive"},
		{"new_secret negative secret_size", `load("totp","new_secret"); new_secret("Acme", "a@b.com", secret_size=-8)`, "secret_size must be positive"},
		{"new_secret bad digits", `load("totp","new_secret"); new_secret("Acme", "a@b.com", digits=10)`, "digits must be 6 or 8"},
		{"new_secret bad algorithm", `load("totp","new_secret"); new_secret("Acme", "a@b.com", algorithm="bcrypt")`, "algorithm must be SHA1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := run(t, tc.script)
			if err == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s: error = %q, want substring %q", tc.name, err.Error(), tc.want)
			}
		})
	}
}

// --- algorithm coverage ------------------------------------------------------

func TestAlgorithmRoundTrips(t *testing.T) {
	const sec = "JBSWY3DPEHPK3PXP"
	// A code minted under one algorithm validates under the same algorithm.
	// SHA1 is the documented default, so an unspecified algorithm must equal
	// an explicit "SHA1".
	algos := []string{"", "SHA1", "SHA256", "SHA512"}
	for _, algo := range algos {
		name := algo
		if name == "" {
			name = "default"
		}
		t.Run(name, func(t *testing.T) {
			script := `
load("totp", "generate_code", "validate")
code = generate_code("` + sec + `", time=1000000000, algorithm="` + algo + `")
ok = validate(code, "` + sec + `", time=1000000000, algorithm="` + algo + `")
`
			res, err := run(t, script)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if res["ok"] != true {
				t.Errorf("%s round-trip = %v, want true", name, res["ok"])
			}
		})
	}

	// The empty/SHA1 default must mint the identical code as explicit "SHA1",
	// and a code minted under SHA256 must NOT validate as SHA1 (the algorithm
	// is actually threaded through, not ignored).
	res, err := run(t, `
load("totp", "generate_code", "validate")
default_code = generate_code("`+sec+`", time=1000000000)
sha1_code    = generate_code("`+sec+`", time=1000000000, algorithm="SHA1")
sha256_code  = generate_code("`+sec+`", time=1000000000, algorithm="SHA256")
same   = default_code == sha1_code
differ = sha1_code != sha256_code
cross  = validate(sha256_code, "`+sec+`", time=1000000000, algorithm="SHA1")
`)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res["same"] != true {
		t.Errorf("default code != explicit SHA1 code")
	}
	if res["differ"] != true {
		t.Errorf("SHA1 and SHA256 produced the same code")
	}
	if res["cross"] != false {
		t.Errorf("SHA256 code validated as SHA1, algorithm not honored")
	}
}

// --- injected clock ----------------------------------------------------------

func TestInjectedClock(t *testing.T) {
	// NewModuleWithClock pins the wall clock the module reads when a script
	// omits time (or passes a non-positive ts). A code generated against the
	// fixed clock must validate against the same fixed clock, and must equal
	// the code generated with an explicit matching time.
	const fixedTS = 1000000000
	mod := NewModuleWithClock(func() time.Time { return time.Unix(fixedTS, 0) })
	res, err := runWithModule(t, mod, `
load("totp", "generate_code", "validate")
# time omitted -> module clock; ts=0 -> module clock; ts=-1 -> module clock.
clock_code   = generate_code("JBSWY3DPEHPK3PXP")
zero_code    = generate_code("JBSWY3DPEHPK3PXP", time=0)
neg_code     = generate_code("JBSWY3DPEHPK3PXP", time=-1)
explicit     = generate_code("JBSWY3DPEHPK3PXP", time=1000000000)
ok           = validate(clock_code, "JBSWY3DPEHPK3PXP")
match_zero   = clock_code == zero_code
match_neg    = clock_code == neg_code
match_exp    = clock_code == explicit
`)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res["ok"] != true {
		t.Errorf("clock-minted code did not validate against the clock")
	}
	if res["match_zero"] != true {
		t.Errorf("time=0 did not fall through to the module clock")
	}
	if res["match_neg"] != true {
		t.Errorf("negative time did not fall through to the module clock")
	}
	if res["match_exp"] != true {
		t.Errorf("clock code != explicit matching-time code")
	}
}

// --- config defaulting + per-call override -----------------------------------

func TestConfigDefaultingAndOverride(t *testing.T) {
	const sec = "JBSWY3DPEHPK3PXP"

	// Setting the digits default via set_default_digits changes the code
	// length when digits is omitted, but a per-call digits keyword still wins
	// (the iron rule: per-call overrides the config default, never the
	// reverse).
	res, err := run(t, `
load("totp", "generate_code", "set_default_digits")
set_default_digits(8)
default_len   = len(generate_code("`+sec+`", time=1000000000))
override_len  = len(generate_code("`+sec+`", time=1000000000, digits=6))
`)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res["default_len"] != int64(8) {
		t.Errorf("default_digits=8 -> code length %v, want 8", res["default_len"])
	}
	if res["override_len"] != int64(6) {
		t.Errorf("per-call digits=6 -> code length %v, want 6 (override ignored)", res["override_len"])
	}

	// The default_period default flows into validation: a code minted under a
	// 60s period validates when the period default is 60 and the keyword is
	// omitted, and the set/get round-trips.
	res, err = run(t, `
load("totp", "generate_code", "validate", "set_default_period", "get_default_period")
set_default_period(60)
got_period = get_default_period()
code = generate_code("`+sec+`", time=1000000000, period=60)
ok   = validate(code, "`+sec+`", time=1000000000)
`)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res["got_period"] != int64(60) {
		t.Errorf("get_default_period = %v, want 60", res["got_period"])
	}
	if res["ok"] != true {
		t.Errorf("code did not validate under the 60s period default")
	}
}

func TestConfigDefaultsFromEnv(t *testing.T) {
	// The env vars are derived from ModuleName: TOTP_DEFAULT_DIGITS /
	// TOTP_DEFAULT_PERIOD. They feed the config defaults, so an omitted digits
	// keyword honors the env value.
	t.Setenv("TOTP_DEFAULT_DIGITS", "8")
	if got := os.Getenv("TOTP_DEFAULT_DIGITS"); got != "8" {
		t.Fatalf("env not set: %q", got)
	}
	res, err := runWithModule(t, NewModule(), `
load("totp", "generate_code")
n = len(generate_code("JBSWY3DPEHPK3PXP", time=1000000000))
`)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res["n"] != int64(8) {
		t.Errorf("TOTP_DEFAULT_DIGITS=8 -> code length %v, want 8", res["n"])
	}
}

// --- hardening ---------------------------------------------------------------

func TestHardeningBounds(t *testing.T) {
	const sec = "JBSWY3DPEHPK3PXP"

	// Absurd skew / secret_size are rejected with a clean Starlark error
	// (never an unbounded HMAC loop or a giant allocation on the host).
	rejects := []struct{ name, script, want string }{
		{"skew over cap", `load("totp","validate"); validate("123456", "` + sec + `", skew=1001)`, "skew must not exceed 1000"},
		{"skew far over cap", `load("totp","validate"); validate("123456", "` + sec + `", skew=2000000000)`, "skew must not exceed 1000"},
		{"secret_size over cap", `load("totp","new_secret"); new_secret("Acme", "a@b.com", secret_size=1025)`, "secret_size must not exceed 1024"},
		{"secret_size far over cap", `load("totp","new_secret"); new_secret("Acme", "a@b.com", secret_size=500000000)`, "secret_size must not exceed 1024"},
	}
	for _, tc := range rejects {
		t.Run(tc.name, func(t *testing.T) {
			_, err := run(t, tc.script)
			if err == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s: error = %q, want substring %q", tc.name, err.Error(), tc.want)
			}
		})
	}

	// The boundary values themselves must still work — the caps reject only
	// what is strictly beyond them, changing no legitimate behavior.
	res, err := run(t, `
load("totp", "validate", "new_secret", "generate_code")
# skew at the cap and at zero are both accepted.
code = generate_code("`+sec+`", time=1000000000)
ok_cap  = validate(code, "`+sec+`", time=1000000000, skew=1000)
ok_zero = validate(code, "`+sec+`", time=1000000000, skew=0)
# secret_size at the cap is accepted and yields a usable secret.
k = new_secret("Acme", "a@b.com", secret_size=1024)
has_secret = len(k.secret) > 0
`)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res["ok_cap"] != true {
		t.Errorf("skew=1000 (the cap) was rejected, want accepted")
	}
	if res["ok_zero"] != true {
		t.Errorf("skew=0 was rejected, want accepted")
	}
	if res["has_secret"] != true {
		t.Errorf("secret_size=1024 (the cap) produced no secret")
	}
}

func TestHardeningInvalidSecretNoPanic(t *testing.T) {
	// A secret that is not valid base32 must surface as a Starlark error
	// (wrapped from the SDK) rather than crashing the host. validate must
	// likewise return an error, not panic.
	cases := []struct{ name, script string }{
		{"generate invalid base32", `load("totp","generate_code"); generate_code("!!! not base32 !!!", time=1000000000)`},
		{"validate invalid base32", `load("totp","validate"); validate("123456", "!!! not base32 !!!", time=1000000000)`},
		{"generate odd-length secret", `load("totp","generate_code"); generate_code("ABC", time=1000000000)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The harness must not panic; an error return is the contract.
			if _, err := run(t, tc.script); err == nil {
				t.Errorf("%s: expected error, got nil", tc.name)
			}
		})
	}
}
