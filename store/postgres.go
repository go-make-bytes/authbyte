// Package store is the identity-mapping store (PostgreSQL). It maps the
// upstream IdP subject to a stable internal subject and keeps a minimal
// profile.
//
// All access goes through SECURITY DEFINER stored procedures (the uniform
// `(pi_data jsonb, INOUT po_data jsonb)` envelope); the service connects with an
// EXECUTE-only role (`authbyte_public`) that has no direct table access. The schema
// and procedures are owned by the separate authbyte-db repo and applied with
// Evolve migrations — this package only CALLs them.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is the PostgreSQL-backed identity mapping store.
type Store struct {
	pool *pgxpool.Pool
}

// New opens a connection pool to PostgreSQL.
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}

	return &Store{pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() {
	s.pool.Close()
}

// Ping verifies connectivity.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("store: ping: %w", err)
	}

	return nil
}

// Profile is the minimal profile stored alongside the mapping. SerialNumber is
// the eIDAS national id (e.g. PNOLV-XXXXXX-XXXXX) — the key the person is deduped
// on across auth methods. LoginMethod records which auth method produced this
// credential (eparakstsMobile, webEid, …) and is stored on the credential row.
type Profile struct {
	Name         string
	GivenName    string
	FamilyName   string
	SerialNumber string
	LoginMethod  string
}

// Mapping is an identity row as returned by identity.get.
type Mapping struct {
	InternalSub  string `json:"internal_sub"`
	IdPSub       string `json:"idp_sub"`
	TenantID     string `json:"tenant_id"`
	Name         string `json:"name"`
	GivenName    string `json:"given_name"`
	FamilyName   string `json:"family_name"`
	SerialNumber string `json:"serial_number"`
}

// envelope is the structured result returned by every procedure
// (util.result_success / util.result_error).
type envelope struct {
	Result  string          `json:"result"`
	Data    json.RawMessage `json:"data"`
	Code    string          `json:"code"`
	Message string          `json:"message"`
}

// call invokes a SECURITY DEFINER procedure with the uniform JSONB envelope and
// returns the decoded `data` payload, or a typed error built from the
// procedure's result_error code/message.
func (s *Store) call(ctx context.Context, proc string, in any) (json.RawMessage, error) {
	inJSON, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("store: marshal input: %w", err)
	}

	// CALL with an INOUT parameter returns a single-column result row carrying
	// the procedure's po_data; NULL seeds the INOUT slot.
	q := fmt.Sprintf("CALL %s($1::jsonb, NULL::jsonb)", proc)

	var out []byte
	if err := s.pool.QueryRow(ctx, q, inJSON).Scan(&out); err != nil {
		// A procedure that fails after a write re-raises a structured error with
		// SQLSTATE P0001 (Pattern B) to force a rollback; its message is the
		// util.result_error JSON. Recover the code/message so callers see the
		// same shape as the validation (returned-error) path.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "P0001" {
			var env envelope
			if json.Unmarshal([]byte(pgErr.Message), &env) == nil && env.Result == "error" {
				return nil, fmt.Errorf("store: %s: %s: %s", proc, env.Code, env.Message)
			}
		}

		return nil, fmt.Errorf("store: %s: %w", proc, err)
	}

	var env envelope
	if err := json.Unmarshal(out, &env); err != nil {
		return nil, fmt.Errorf("store: %s: decode result: %w", proc, err)
	}
	if env.Result != "success" {
		return nil, fmt.Errorf("store: %s: %s: %s", proc, env.Code, env.Message)
	}

	return env.Data, nil
}

// EnsureMapping resolves a login to the stable PERSON subject and links the
// auth-method credential. The person is keyed on the eIDAS national id
// (p.SerialNumber), so the SAME human authenticating through different methods
// (eParaksts Mobile vs Web eID card) — which present DIFFERENT idpSubject values —
// resolves to ONE internal subject instead of one identity per method. The
// returned bool is true only when the PERSON was created on this call (their
// first-ever login, by any method) so the caller records the correct GDPR-audit
// event (identity created vs updated); adding a new method to a known person is an
// update. Implemented via the identity.upsert procedure (no direct table access).
func (s *Store) EnsureMapping(ctx context.Context, idpSubject string, p Profile) (string, bool, error) {
	data, err := s.call(ctx, "identity.upsert", map[string]any{
		"idp_sub":       idpSubject,
		"name":          p.Name,
		"given_name":    p.GivenName,
		"family_name":   p.FamilyName,
		"serial_number": p.SerialNumber, // the national id — the person key
		"login_method":  p.LoginMethod,
	})
	if err != nil {
		return "", false, err
	}

	var res struct {
		InternalSub string `json:"internal_sub"`
		Created     bool   `json:"created"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return "", false, fmt.Errorf("store: ensure mapping: decode: %w", err)
	}

	return res.InternalSub, res.Created, nil
}

// Get reads an identity by internal subject (via the identity.get procedure).
func (s *Store) Get(ctx context.Context, internalSubject string) (Mapping, error) {
	var m Mapping

	data, err := s.call(ctx, "identity.get", map[string]any{
		"internal_sub": internalSubject,
	})
	if err != nil {
		return m, err
	}

	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("store: get: decode: %w", err)
	}

	return m, nil
}
