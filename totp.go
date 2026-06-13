// Package totp provides a Starlark module for TOTP (time-based one-time
// password, RFC 6238) generation and validation. It is pure computation built
// on github.com/pquerna/otp.
package totp

import (
	"fmt"
	"strings"
	"time"

	"github.com/1set/starlet"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/starpkg/base"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// ModuleName is the name used in Starlark's load() for this module.
const ModuleName = "totp"

const (
	configKeyDefaultPeriod = "default_period"
	configKeyDefaultDigits = "default_digits"
)

const (
	defaultPeriod = 30
	defaultDigits = 6
)

var none = starlark.None

// Module wraps a ConfigurableModule with TOTP functions.
type Module struct {
	cfgMod *base.ConfigurableModule
	ext    *base.ConfigurableModuleExt
	clock  func() time.Time
}

// NewModule creates a Module using the wall clock.
func NewModule() *Module { return newModule(time.Now) }

// NewModuleWithClock creates a Module with an injected clock (for deterministic
// testing). clock must be non-nil.
func NewModuleWithClock(clock func() time.Time) *Module { return newModule(clock) }

func newModule(clock func() time.Time) *Module {
	cm, _ := base.NewConfigurableModuleWithConfigOptions(
		genConfigOption(configKeyDefaultPeriod, "Default TOTP period in seconds", defaultPeriod),
		genConfigOption(configKeyDefaultDigits, "Default number of code digits (6 or 8)", defaultDigits),
	)
	return &Module{cfgMod: cm, ext: cm.Extend(), clock: clock}
}

func genConfigOption[T any](name, description string, defaultValue T) *base.ConfigOption[T] {
	return base.NewConfigOption(defaultValue).
		WithName(name).
		WithDescription(description).
		WithEnvVar(strings.ToUpper(ModuleName + "_" + name))
}

// LoadModule returns the Starlark module loader.
func (m *Module) LoadModule() starlet.ModuleLoader {
	funcs := starlark.StringDict{
		"generate_code": starlark.NewBuiltin(ModuleName+".generate_code", m.generateCode),
		"validate":      starlark.NewBuiltin(ModuleName+".validate", m.validate),
		"new_secret":    starlark.NewBuiltin(ModuleName+".new_secret", m.newSecret),
	}
	return m.cfgMod.LoadModule(ModuleName, funcs)
}

func resolveDigits(d int) (otp.Digits, error) {
	switch d {
	case 6:
		return otp.DigitsSix, nil
	case 8:
		return otp.DigitsEight, nil
	default:
		return 0, fmt.Errorf("digits must be 6 or 8, got %d", d)
	}
}

func resolveAlgorithm(name string) (otp.Algorithm, error) {
	switch name {
	case "", "SHA1":
		return otp.AlgorithmSHA1, nil
	case "SHA256":
		return otp.AlgorithmSHA256, nil
	case "SHA512":
		return otp.AlgorithmSHA512, nil
	default:
		return 0, fmt.Errorf("algorithm must be SHA1, SHA256, or SHA512, got %q", name)
	}
}

// at resolves the evaluation time: ts>0 means that Unix second, else the clock.
func (m *Module) at(ts int64) time.Time {
	if ts > 0 {
		return time.Unix(ts, 0)
	}
	return m.clock()
}

// generate_code(secret, time=0, period=<cfg>, digits=<cfg>, algorithm="SHA1") -> str
func (m *Module) generateCode(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var (
		secret    string
		ts        = int64(0)
		period    = m.ext.GetInt(configKeyDefaultPeriod)
		digits    = m.ext.GetInt(configKeyDefaultDigits)
		algorithm = "SHA1"
	)
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"secret", &secret, "time?", &ts, "period?", &period, "digits?", &digits, "algorithm?", &algorithm,
	); err != nil {
		return none, err
	}
	if secret == "" {
		return none, fmt.Errorf("%s: secret must not be empty", b.Name())
	}
	if period <= 0 {
		return none, fmt.Errorf("%s: period must be positive", b.Name())
	}
	d, err := resolveDigits(digits)
	if err != nil {
		return none, fmt.Errorf("%s: %w", b.Name(), err)
	}
	a, err := resolveAlgorithm(algorithm)
	if err != nil {
		return none, fmt.Errorf("%s: %w", b.Name(), err)
	}
	code, err := totp.GenerateCodeCustom(secret, m.at(ts), totp.ValidateOpts{
		Period: uint(period), Digits: d, Algorithm: a,
	})
	if err != nil {
		return none, fmt.Errorf("totp: %w", err)
	}
	return starlark.String(code), nil
}

// validate(code, secret, time=0, period=<cfg>, digits=<cfg>, skew=1, algorithm="SHA1") -> bool
func (m *Module) validate(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var (
		code      string
		secret    string
		ts        = int64(0)
		period    = m.ext.GetInt(configKeyDefaultPeriod)
		digits    = m.ext.GetInt(configKeyDefaultDigits)
		skew      = 1
		algorithm = "SHA1"
	)
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"code", &code, "secret", &secret, "time?", &ts, "period?", &period,
		"digits?", &digits, "skew?", &skew, "algorithm?", &algorithm,
	); err != nil {
		return none, err
	}
	if secret == "" {
		return none, fmt.Errorf("%s: secret must not be empty", b.Name())
	}
	if period <= 0 {
		return none, fmt.Errorf("%s: period must be positive", b.Name())
	}
	if skew < 0 {
		return none, fmt.Errorf("%s: skew must not be negative", b.Name())
	}
	d, err := resolveDigits(digits)
	if err != nil {
		return none, fmt.Errorf("%s: %w", b.Name(), err)
	}
	a, err := resolveAlgorithm(algorithm)
	if err != nil {
		return none, fmt.Errorf("%s: %w", b.Name(), err)
	}
	ok, err := totp.ValidateCustom(code, secret, m.at(ts), totp.ValidateOpts{
		Period: uint(period), Skew: uint(skew), Digits: d, Algorithm: a,
	})
	if err != nil {
		return none, fmt.Errorf("totp: %w", err)
	}
	return starlark.Bool(ok), nil
}

// new_secret(issuer, account_name, period=<cfg>, digits=<cfg>, algorithm="SHA1", secret_size=20) -> struct(secret, url)
func (m *Module) newSecret(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var (
		issuer     string
		account    string
		period     = m.ext.GetInt(configKeyDefaultPeriod)
		digits     = m.ext.GetInt(configKeyDefaultDigits)
		algorithm  = "SHA1"
		secretSize = 20
	)
	if err := starlark.UnpackArgs(b.Name(), args, kwargs,
		"issuer", &issuer, "account_name", &account, "period?", &period,
		"digits?", &digits, "algorithm?", &algorithm, "secret_size?", &secretSize,
	); err != nil {
		return none, err
	}
	if issuer == "" || account == "" {
		return none, fmt.Errorf("%s: issuer and account_name are required", b.Name())
	}
	if secretSize <= 0 {
		return none, fmt.Errorf("%s: secret_size must be positive", b.Name())
	}
	d, err := resolveDigits(digits)
	if err != nil {
		return none, fmt.Errorf("%s: %w", b.Name(), err)
	}
	a, err := resolveAlgorithm(algorithm)
	if err != nil {
		return none, fmt.Errorf("%s: %w", b.Name(), err)
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: issuer, AccountName: account, Period: uint(period),
		Digits: d, Algorithm: a, SecretSize: uint(secretSize),
	})
	if err != nil {
		return none, fmt.Errorf("totp: %w", err)
	}
	return starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{
		"secret": starlark.String(key.Secret()),
		"url":    starlark.String(key.URL()),
	}), nil
}
