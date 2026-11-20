package main

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"

	"gopkg.in/yaml.v2"

	"github.com/tinfoilsh/confidential-model-router/cacheroute"
	"github.com/tinfoilsh/confidential-model-router/config"
)

// secretEnvFlags maps each secret flag to the env var it falls back to.
var secretEnvFlags = map[string]string{
	"usage-reporter-secret": "USAGE_REPORTER_SECRET",
	"usage-context-secret":  "USAGE_CONTEXT_SECRET",
	"cache-route-secret":    "CACHE_ROUTE_SECRET",
	"metrics-api-key":       "METRICS_API_KEY",
}

const secretFlagCanary = "canary-secret-must-not-print"

// Flag defaults are fixed at package init, from the environment the process
// starts with. The child process starts with every secret set, so a default
// read from the environment shows up in -h output.
func TestSecretFlagDefaultsOmitEnv(t *testing.T) {
	if os.Getenv("ROUTER_SECRET_FLAG_CHILD") == "1" {
		var usage bytes.Buffer
		flag.CommandLine.SetOutput(&usage)
		flag.CommandLine.PrintDefaults()
		for name := range secretEnvFlags {
			if f := flag.Lookup(name); f == nil || f.DefValue != "" {
				t.Errorf("flag %s missing or has a default", name)
			}
		}
		if strings.Contains(usage.String(), secretFlagCanary) {
			t.Error("-h output prints a secret")
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSecretFlagDefaultsOmitEnv$", "-test.count=1")
	cmd.Env = append(os.Environ(), "ROUTER_SECRET_FLAG_CHILD=1")
	for _, env := range secretEnvFlags {
		cmd.Env = append(cmd.Env, env+"="+secretFlagCanary)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, strings.ReplaceAll(string(out), secretFlagCanary, "<canary>"))
	}
}

func TestReleaseConfigSecurityRequirements(t *testing.T) {
	cfg, err := config.FromBytes(configFile)
	if err != nil {
		t.Fatalf("embedded config is invalid: %v", err)
	}
	cacheroute.SetSecret(strings.Repeat("x", 32))
	t.Cleanup(func() { cacheroute.SetSecret("") })
	if err := cacheroute.ValidateSecret(cfg); err != nil {
		t.Fatalf("embedded cache routing config is invalid: %v", err)
	}
	for name, model := range cfg.Models {
		if model.Overload.Enabled() && model.Overload.LocalInflightCap() <= 0 {
			t.Errorf("model %s has overload routing without a local in-flight cap", name)
		}
	}

	manifestBytes, err := os.ReadFile("tinfoil-config.yml")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Containers []struct {
			Name    string   `yaml:"name"`
			Secrets []string `yaml:"secrets"`
		} `yaml:"containers"`
	}
	if err := yaml.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("release manifest is invalid: %v", err)
	}
	found := false
	for _, container := range manifest.Containers {
		if container.Name != "router" {
			continue
		}
		for _, secret := range container.Secrets {
			if secret == "CACHE_ROUTE_SECRET" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("router release manifest does not declare CACHE_ROUTE_SECRET")
	}
}

func TestSecretFlagOrEnv(t *testing.T) {
	t.Setenv("ROUTER_TEST_SECRET", "from-env")
	if got := secretFlagOrEnv("from-flag", "ROUTER_TEST_SECRET"); got != "from-flag" {
		t.Fatalf("flag value lost: %q", got)
	}
	if got := secretFlagOrEnv("", "ROUTER_TEST_SECRET"); got != "from-env" {
		t.Fatalf("env fallback lost: %q", got)
	}
}
