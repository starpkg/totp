package totp

// Tests for the totp module.
//
// Sections:
//   - generate/validate round-trip at a fixed time
//   - new_secret
//   - option validation errors (bad digits/algorithm, empty secret, non-positive period)

import (
	"strings"
	"testing"

	"github.com/1set/starlet"
)

func run(t *testing.T, script string) (map[string]interface{}, error) {
	t.Helper()
	m := starlet.NewDefault()
	m.SetScriptContent([]byte(script))
	m.SetLazyloadModules(map[string]starlet.ModuleLoader{ModuleName: NewModule().LoadModule()})
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
	cases := map[string]string{
		"bad digits":               `load("totp","generate_code"); generate_code("JBSWY3DPEHPK3PXP", digits=7)`,
		"bad algorithm":            `load("totp","generate_code"); generate_code("JBSWY3DPEHPK3PXP", algorithm="MD5")`,
		"empty issuer":             `load("totp","new_secret"); new_secret("", "a@b.com")`,
		"generate empty secret":    `load("totp","generate_code"); generate_code("")`,
		"generate zero period":     `load("totp","generate_code"); generate_code("JBSWY3DPEHPK3PXP", period=0)`,
		"generate negative period": `load("totp","generate_code"); generate_code("JBSWY3DPEHPK3PXP", period=-5)`,
		"validate empty secret":    `load("totp","validate"); validate("123456", "")`,
		"validate zero period":     `load("totp","validate"); validate("123456", "JBSWY3DPEHPK3PXP", period=0)`,
	}
	for name, script := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := run(t, script); err == nil {
				t.Errorf("%s: expected error, got nil", name)
			}
		})
	}
}
