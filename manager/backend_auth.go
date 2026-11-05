package manager

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/tinfoilsh/confidential-model-router/config"
)

type backendTarget struct{ model, host string }

// Published once at startup; never mutated or serialized.
type backendCredentials map[backendTarget]string

type backendCredentialsKey struct{}
type originalIdentityKey struct{}
type backendRequestCredentials struct {
	credentials backendCredentials
	model       string
}

func loadBackendCredentials(cfg *config.Config) (backendCredentials, error) {
	credentials := make(backendCredentials)
	values := make(map[string]string)
	for model, c := range cfg.Models {
		if c.BackendAuthEnv == "" {
			continue
		}
		value, ok := values[c.BackendAuthEnv]
		if !ok {
			value = os.Getenv(c.BackendAuthEnv)
			if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\r\n") {
				return nil, fmt.Errorf("model %s: backend_auth_env %s must contain a nonempty bearer credential", model, c.BackendAuthEnv)
			}
			values[c.BackendAuthEnv] = value
		}
		for _, host := range c.Hostnames {
			u, err := url.Parse("https://" + host)
			if err != nil || u.Host != host || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
				return nil, fmt.Errorf("model %s: invalid backend_auth_env target hostname", model)
			}
			credentials[backendTarget{model, host}] = "Bearer " + value
		}
	}
	return credentials, nil
}

func (c backendCredentials) hasModel(model string) bool {
	for target := range c {
		if target.model == model {
			return true
		}
	}
	return false
}

func withBackendCredentials(ctx context.Context, credentials backendCredentials, model string) context.Context {
	return context.WithValue(ctx, backendCredentialsKey{}, backendRequestCredentials{credentials, model})
}

func withOriginalIdentity(ctx context.Context, authorization string) context.Context {
	if _, ok := ctx.Value(originalIdentityKey{}).(string); ok {
		return ctx
	}
	return context.WithValue(ctx, originalIdentityKey{}, authorization)
}

func applyBackendAuthorization(req *http.Request) {
	state, ok := req.Context().Value(backendCredentialsKey{}).(backendRequestCredentials)
	if !ok || req.URL.Scheme != "https" {
		return
	}
	if authorization := state.credentials[backendTarget{state.model, req.URL.Host}]; authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
}

type backendAuthTripper struct{ base http.RoundTripper }

func (t *backendAuthTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	if authorization, ok, err := authorizationFromContext(out.Context()); err != nil {
		return nil, fmt.Errorf("resolve delegated authorization: %w", err)
	} else if ok {
		out.Header.Set("Authorization", authorization)
	}
	applyBackendAuthorization(out)
	return t.base.RoundTrip(out)
}
