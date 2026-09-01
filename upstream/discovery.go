package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// discoveryDocument is the subset of the OIDC discovery document
// (/.well-known/openid-configuration) the connector consumes.
type discoveryDocument struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// discover resolves the provider's endpoints from its discovery document and
// fills only the Config fields that are still empty — an explicit endpoint URL
// always wins over a discovered one. Startup fails closed on any error: a
// provider whose endpoints cannot be established must not come up half-wired.
func discover(ctx context.Context, httpc *http.Client, cfg *Config) error {
	if cfg.AuthorityURL == "" {
		return fmt.Errorf("oidc: no authority URL and no explicit endpoints configured")
	}

	wellKnown := cfg.AuthorityURL + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpc.Do(req)
	if err != nil {
		return fmt.Errorf("oidc: discovery request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("oidc: discovery returned %d: %s", resp.StatusCode, body)
	}

	var doc discoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("oidc: invalid discovery document: %w", err)
	}

	if cfg.AuthorizeURL == "" {
		cfg.AuthorizeURL = doc.AuthorizationEndpoint
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = doc.TokenEndpoint
	}
	if cfg.UserInfoURL == "" {
		cfg.UserInfoURL = doc.UserInfoEndpoint
	}
	if cfg.EndSessionURL == "" {
		cfg.EndSessionURL = doc.EndSessionEndpoint
	}

	if cfg.AuthorizeURL == "" || cfg.TokenURL == "" || cfg.UserInfoURL == "" {
		return fmt.Errorf("oidc: discovery document at %s is missing required endpoints", wellKnown)
	}

	return nil
}
